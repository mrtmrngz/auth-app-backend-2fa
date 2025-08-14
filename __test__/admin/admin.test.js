import request from "supertest";
import mongoose from "mongoose";
import User from "../../models/User.model.js";
import app from "../../app.js";
import {generateAccessToken} from "../../libs/generateTokens.js";
import bcrypt from "bcrypt";
import path from "path";
import cloudinary from 'cloudinary'

beforeAll(async () => {

    if (mongoose.connection.readyState === 1) {
        await mongoose.disconnect();
    }

    await mongoose.connect(process.env.MONGO_URI_TEST)
})

afterAll(async () => {
    await mongoose.connection.close()
})

describe("Admin test", () => {

    let cloudinaryUploadSpy;

    beforeAll(() => {
        jest.spyOn(console, 'error').mockImplementation((msg) => {
            if (msg instanceof Error && msg.statusCode) {
                return;
            }
            process.stderr.write(`${msg}\n`);
        });

        jest.spyOn(console, 'warn').mockImplementation(() => {});

        cloudinaryUploadSpy = jest.spyOn(cloudinary.v2.uploader, 'upload').mockResolvedValue({
            url: "https://mocked-url/testavatar_mock.jpg",
            public_id: "testavatar_public_id_mock",
        })

        jest.spyOn(cloudinary.v2.uploader, 'destroy').mockResolvedValue({
            result: 'ok'
        })
    });

    afterEach(async () => {
        await User.deleteMany();
    });

    // ADMIN AUTHORIZE

    test('should return 401 if user not authenticated', async () => {

        const response = await request(app).get("/api/admin/dashboard")

        expect(response.statusCode).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Unauthorized");
    })

    test('should return 403 if user authenticated but not admin role', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: true,
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).get("/api/admin/dashboard").set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(403);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Forbidden: You are not allowed to access this route.");
    })

    test('should return 200 and has access true if user role is admin', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).get("/api/admin/has-access").set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.hasAccess).toBe(true);
    })

    // ADMIN DASHBOARD

    test('should return 200 and dashboard if everything ok', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).get("/api/admin/dashboard").set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(200);
        expect(response.body).toEqual(expect.objectContaining({
            weekly_registration: [
                {
                    _id: expect.any(String),
                    count: expect.any(Number)
                }
            ],
            last_ten: [
                {
                    avatar: {
                        url: test_user.avatar.url,
                        public_id: test_user.avatar.public_id
                    },
                    _id: test_user._id.toString(),
                    username: test_user.username,
                    email: test_user.email,
                    role: test_user.role
                }
            ],
            banned_users: [],
            total_user_count: 1,
            verified_user_count: 1,
            unverified_user_count: 0,
            success: true
        }))
    })

    // ADMIN BAN USER

    test('should return 400 if required fields are missing', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const banned_user = await User.create({
            username: "banned",
            email: 'banned1@mail.com',
            password: "123"
        })

        const data = {
            banned_user_id: banned_user._id
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/ban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("The ID of the user you want to ban, the reason for the ban, and the ban expiration date are required.");
    })

    test('should return 404 if user not found', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const data = {
            user_id: "689d06f02109cb7f018af8e9",
            reason: "test",
            expire: "P"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/ban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found");
    })

    test('should return 409 if user already banned', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const banned_user = await User.create({
            username: "banned",
            email: 'banned1@mail.com',
            password: "123",
            ban_status: {
                is_banned: true,
                ban_expire: null,
                ban_reason: "test"
            }
        })

        const data = {
            user_id: banned_user._id,
            reason: "test",
            expire: "P"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/ban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User already banned");
    })

    test('should return 200 if everything ok', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const banned_user = await User.create({
            username: "banned",
            email: 'banned1@mail.com',
            password: "123"
        })

        const data = {
            user_id: banned_user._id,
            reason: "test",
            expire: "P"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/ban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("User Banned");
    })

    // ADMIN UNBAN USER

    test('should return 400 if required fields are missing', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const banned_user = await User.create({
            username: "banned",
            email: 'banned1@mail.com',
            password: "123"
        })

        const data = {
            banned_user_id: banned_user._id
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/unban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User id required!");
    })

    test('should return 404 if user not found', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const data = {
            user_id: "689d06f02109cb7f018af8e9",
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/unban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found");
    })

    test('should return 409 if user already unbanned', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const banned_user = await User.create({
            username: "banned",
            email: 'banned1@mail.com',
            password: "123"
        })

        const data = {
            user_id: banned_user._id,
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/unban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("The user is not already banned");
    })

    test('should return 200 if everything ok', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const banned_user = await User.create({
            username: "banned",
            email: 'banned1@mail.com',
            password: "123",
            ban_status: {
                is_banned: true,
                ban_expire: null,
                ban_reason: "test"
            }
        })

        const data = {
            user_id: banned_user._id,
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/admin/unban-user").send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("User ban removed");
    })

    // ADMIN USER EDIT

    test('should return 400 if required fields are missing', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const editing_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const data = {
            invalid_field: 1
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch(`/api/admin/update-user/${editing_user._id}`).send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("At least 1 field is required");
    })

    test('should return 404 if user not found', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const editing_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const data = {
            username: "test",
            email: 'test@gmail.com',
            role: "USER"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch(`/api/admin/update-user/689d06f02109cb7f018af8e9`).send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found!");
    })

    test('should return 409 if another user exist sent email or username from email', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const editing_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const data = {
            username: "test_user",
            email: 'test@mail.com',
            role: "USER"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch(`/api/admin/update-user/${editing_user._id}`).send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("A user with this username or email address already exists.");
    })

    test('should return 409 if user send invalid role', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const editing_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const data = {
            username: "test",
            email: 'test@gmail.com',
            role: "TEST"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch(`/api/admin/update-user/${editing_user._id}`).send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Invalid role");
    })

    test('should return 200 if everything ok (without file)', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const editing_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const data = {
            username: "test",
            email: 'test@gmail.com',
            role: "USER"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch(`/api/admin/update-user/${editing_user._id}`).send(data).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("User updated successfully");
    })

    test('should return 200 if everything ok (only avatar)', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const editing_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const file1 = path.join(__dirname, '../test-assets/dummy-image.png')

        const response = await request(app).patch(`/api/admin/update-user/${editing_user._id}`).set("Authorization", `Bearer ${token}`).attach('avatar', file1)

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("User updated successfully");

        const updated_user = await User.findById(editing_user._id)
        expect(updated_user.avatar.url).toEqual("https://mocked-url/testavatar_mock.jpg")
        expect(updated_user.avatar.public_id).toEqual("testavatar_public_id_mock")
    })

    test('should return 200 if everything ok (all fields)', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const editing_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const data = {
            username: "test",
            email: 'test@gmail.com',
            role: "USER"
        }

        const token = generateAccessToken(test_user._id, test_user.role)

        const file1 = path.join(__dirname, '../test-assets/dummy-image.png')

        const response = await request(app)
            .patch(`/api/admin/update-user/${editing_user._id}`)
            .set("Authorization", `Bearer ${token}`)
            .field('username', data.username)
            .field('email', data.email)
            .field('role', data.role)
            .attach('avatar', file1)
        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("User updated successfully");

        const updated_user = await User.findById(editing_user._id)
        expect(updated_user.avatar.url).toEqual("https://mocked-url/testavatar_mock.jpg")
        expect(updated_user.avatar.public_id).toEqual("testavatar_public_id_mock")
    })

    // DELETE USER

    test('should return 404 if user not found', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const deleting_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).delete(`/api/admin/delete-user/689d06f02109cb7f018af8e9`).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found!");
    })

    test('should return 200 if everything ok', async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            role: "ADMIN",
            avatar: {
                url: "old-avatar-url.jpg",
                public_id: "old-avatar-public-id"
            }
        })

        const deleting_user = await User.create({
            username: "editing",
            email: 'editing@mail.com',
            password: "123"
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).delete(`/api/admin/delete-user/${deleting_user._id}`).set("Authorization", `Bearer ${token}`)
        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("User deleted successfully");

        const found_user = await User.findById(deleting_user._id)

        expect(found_user).toBeNull()
    })
})

