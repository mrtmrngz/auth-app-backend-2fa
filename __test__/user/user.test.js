import request from "supertest";
import mongoose from "mongoose";
import User from "../../models/User.model.js";
import app from "../../app.js";
import {generateAccessToken} from "../../libs/generateTokens.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import path from 'path'
import cloudinary from "cloudinary";

beforeAll(async () => {

    if (mongoose.connection.readyState === 1) {
        await mongoose.disconnect();
    }

    await mongoose.connect(process.env.MONGO_URI_TEST)
})

afterAll(async () => {
    await mongoose.connection.close()
})

describe("User test", () => {
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
            secure_url: "https://mocked-url/testavatar_mock.jpg",
            public_id: "testavatar_public_id_mock",
        });

        jest.spyOn(cloudinary.v2.uploader, 'destroy').mockResolvedValue({
            result: "ok"
        });
    });

    afterEach(async () => {
        await User.deleteMany();
    });

    // USER INFO TESTS

    test("should return 401 if no token is provided", async () => {

        const response = await request(app).get("/api/users/user-info")

        expect(response.statusCode).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Unauthorized!")
    })

    test("should return 404 if user not found", async () => {

        const token = generateAccessToken("507f1f77bcf86cd799439011", "role")

        const response = await request(app).get("/api/users/user-info").set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found")
    })

    test("should return 409 if user unverified", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).get("/api/users/user-info").set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Email not verified. Please verified your email first")
    })

    test("should return 200 and send user if everything ok", async () => {

            const hashedPassword = await bcrypt.hash("test123", 10)

            const test_user = await User.create({
                username: "test_user",
                email: "test_user@mail.com",
                password: hashedPassword,
                isVerified: true,
                avatar: {
                    url: "testavatar_url",
                    public_id: "testavatar_public_id",
                }
            })

            const token = generateAccessToken(test_user._id, test_user.role)

            const response = await request(app).get("/api/users/user-info").set("Authorization", `Bearer ${token}`)

            expect(response.statusCode).toBe(200);
            expect(response.body).toEqual(expect.objectContaining({
                _id: test_user._id.toString(),
                username: test_user.username,
                email: test_user.email,
                isVerified: true,
                role: "USER",
                avatar: {
                    url: "testavatar_url",
                    public_id: "testavatar_public_id",
                }
            }))
        })

    // ENABLE 2FA TESTS

    test("should return 401 if no token is provided", async () => {

        const response = await request(app).patch("/api/users/enable-two-factor")

        expect(response.statusCode).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Unauthorized!")
    })

    test("should return 404 if user not found", async () => {

        const token = generateAccessToken("507f1f77bcf86cd799439011", "role")

        const response = await request(app).patch("/api/users/enable-two-factor").set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found")
    })

    test("should return 409 if user 2fa already active", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: true
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/users/enable-two-factor").set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(409);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("2FA already active")
    })

    test("should return 200 and token if everything OK", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: false
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const response = await request(app).patch("/api/users/enable-two-factor").set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("The 6-digit code has been sent to your email address.")
        expect(response.body.token).toBeDefined()

        const mail_token = jwt.verify(response.body.token, process.env.JWT_MAIL_SECRET)

        expect(mail_token).toHaveProperty("id")
        expect(mail_token).toHaveProperty("otpType", "TWO_FACTOR")
    })

    // CHANGE MAIL AND USERNAME

    test("should return 401 if no token is provided", async () => {

        const response = await request(app).patch("/api/users/change-mail-or-username")

        expect(response.statusCode).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Unauthorized!")
    })

    test("should return 400 if send invalid changetype", async () => {

        const token = generateAccessToken("507f1f77bcf86cd799439011", "role")

        const data = {
            changeType: "INVALID_TYPE"
        }

        const response = await request(app).patch("/api/users/change-mail-or-username").send(data).set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Invalid Change Type")
    })

    test("should return 400 if change type is email but email is missing!", async () => {

        const token = generateAccessToken("507f1f77bcf86cd799439011", "role")

        const data = {
            changeType: "EMAIL_CHANGE",
        }

        const response = await request(app).patch("/api/users/change-mail-or-username").send(data).set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Email Required")
    })

    test("should return 400 if change type is username but username is missing!", async () => {

        const token = generateAccessToken("507f1f77bcf86cd799439011", "role")

        const data = {
            changeType: "USERNAME_CHANGE",
        }

        const response = await request(app).patch("/api/users/change-mail-or-username").send(data).set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Username Required")
    })

    test("should return 404 if user not found", async () => {

        const token = generateAccessToken("507f1f77bcf86cd799439011", "role")

        const data = {
            changeType: "USERNAME_CHANGE",
            username: "test"
        }

        const response = await request(app).patch("/api/users/change-mail-or-username").send(data).set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found")
    })

    test("should return 400 if everything ok but another user already exist sent mail", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: true
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const data = {
            changeType: "EMAIL_CHANGE",
            email: "test_user@mail.com"
        }

        const response = await request(app).patch("/api/users/change-mail-or-username").send(data).set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Existing user!")
    })

    test("should return 400 if everything ok but another user already exist sent username", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: true
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const data = {
            changeType: "USERNAME_CHANGE",
            username: "test_user"
        }

        const response = await request(app).patch("/api/users/change-mail-or-username").send(data).set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(400);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Existing user!")
    })

    test("should return 200 and token if everything ok", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            username: "test_user",
            email: "test_user@mail.com",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: true
        })

        const token = generateAccessToken(test_user._id, test_user.role)

        const data = {
            changeType: "USERNAME_CHANGE",
            username: "test_user_changed"
        }

        const response = await request(app).patch("/api/users/change-mail-or-username").send(data).set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("The 6-digit code has been sent to your email address.")
        expect(response.body.token).toBeDefined()

        const mail_token = jwt.verify(response.body.token, process.env.JWT_MAIL_SECRET)
        expect(mail_token).toHaveProperty('id')
        expect(mail_token).toHaveProperty('otpType', "USERNAME_CHANGE")
    })

    // CHANGE OTHER INFOS TEST

    test("should return 401 if no token is provided", async () => {

        const response = await request(app).patch("/api/users/change-user-infos")

        expect(response.statusCode).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Unauthorized!")
    })

    test("should return 404 if user not found", async () => {

        const token = generateAccessToken("507f1f77bcf86cd799439011", "role")

        const response = await request(app).patch("/api/users/change-user-infos").set("Authorization", `Bearer ${token}`)

        expect(response.statusCode).toBe(404);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("User not found")
    })

    test("should return 200 if everything ok", async () => {

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

        const filePath = path.join(__dirname, "../test-assets/dummy-image.png")

        const response = await request(app).patch("/api/users/change-user-infos").set("Authorization", `Bearer ${token}`).attach('avatar', filePath)

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("User updated successfully!");

        expect(cloudinaryUploadSpy).toHaveBeenCalled();

        const updatedUser = await User.findById(test_user._id);
        expect(updatedUser.avatar.url).toEqual("https://mocked-url/testavatar_mock.jpg");
        expect(updatedUser.avatar.public_id).toEqual("testavatar_public_id_mock");
    })
})

