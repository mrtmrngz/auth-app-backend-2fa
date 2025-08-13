import request from "supertest";
import mongoose from "mongoose";
import User from "../../models/User.model.js";
import app from "../../app.js";
import jwt from 'jsonwebtoken'
import {generateMailToken} from "../../libs/generateTokens.js";
import bcrypt from "bcrypt";

beforeAll(async () => {

    if (mongoose.connection.readyState === 1) {
        await mongoose.disconnect();
    }

    await mongoose.connect(process.env.MONGO_URI_TEST)
})

afterAll(async () => {
    await mongoose.connection.close()
})

describe("Login test", () => {

    beforeAll(() => {
        jest.spyOn(console, 'error').mockImplementation((msg) => {
            if (msg instanceof Error && msg.statusCode) {
                return;
            }
            process.stderr.write(`${msg}\n`);
        });

        jest.spyOn(console, 'warn').mockImplementation(() => {});
    });

    afterEach(async () => {
        await User.deleteMany();
    });

    test("Incomplete information should result in failure", async () => {

        await User.create({
            email: "testmail@test.com",
            username: "testuser123",
            password: "test123",
            isVerified: true
        })

        const login_user = {
            email: `testmail@test.com`,
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Email and Password are required!")
    })

    test("If the user is not found, a failed result should be returned.", async () => {

        await User.create({
            email: "testmail@test.com",
            username: "testuser123",
            password: "test123",
            isVerified: true
        })

        const login_user = {
            email: `testmail1@test.com`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(401);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Invalid credentials!")
    })

    test("If the user is not verified, an error should be returned.", async () => {

        await User.create({
            email: "testmail@test.com",
            username: "testuser123",
            password: "test123",
            isVerified: false
        })

        const login_user = {
            email: `testmail@test.com`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(401);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("User not verified")
    })

    test("If the user is banned, a failed result should be returned. (not permanent ban)", async () => {

        const banned_user = await User.create({
            email: "testmailbanned@test.com",
            username: "testuser123banned",
            password: "test123",
            isVerified: true,
            ban_status: {
                is_banned: true,
                ban_expire: new Date(Date.now() + (1000 * 60 * 5)),
                ban_reason: "TEST"
            }
        })

        const login_user = {
            email: `testmailbanned@test.com`,
            password: "testuser123banned"
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(403);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toMatch(/You are currently banned/)
    })

    test("If the user is banned, a failed result should be returned. (permanent ban)", async () => {

        const banned_user = await User.create({
            email: "testmailbanned@test.com",
            username: "testuser123banned",
            password: "test123",
            isVerified: true,
            ban_status: {
                is_banned: true,
                ban_expire: null,
                ban_reason: "TEST"
            }
        })

        const login_user = {
            email: `testmailbanned@test.com`,
            password: "testuser123banned"
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(403);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("You are banned!")
    })

    test("If the password is incorrect, it will return a failed result.", async () => {

        await User.create({
            email: "testmail@test.com",
            username: "testuser123",
            password: "test123",
            isVerified: true
        })

        const login_user = {
            email: `testmail@test.com`,
            password: "test1234"
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(401);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Invalid credentials!")
    })

    test("If all information is correct and if the user does not have 2FA enabled, it will return an access token.", async () => {

        const hashedPass = await bcrypt.hash("test123", 10)

        await User.create({
            email: "testmail@test.com",
            username: "testuser123",
            password: hashedPass,
            isVerified: true,
            isTwoFactorEnabled: false
        })

        const login_user = {
            email: `testmail@test.com`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("Login Successful")
        expect(response.body.accessToken).toBeDefined()

        const refresh_token_session_cookie = response.headers["set-cookie"].find(cookie => cookie.startsWith("_session="))
        expect(refresh_token_session_cookie).toBeDefined()
        expect(refresh_token_session_cookie).toContain("HttpOnly")

        const decoded = jwt.verify(response.body.accessToken, process.env.JWT_ACCESS_SECRET)
        expect(decoded).toHaveProperty("id")
        expect(decoded).toHaveProperty("role")
    })

    test("If the user has 2FA enabled, it must send a token.", async () => {

        const hashedPass = await bcrypt.hash("test123", 10)

        await User.create({
            email: "testmail@test.com",
            username: "testuser123",
            password: hashedPass,
            isVerified: true,
            isTwoFactorEnabled: true
        })

        const login_user = {
            email: `testmail@test.com`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/login").send(login_user).set("Accept", "application/json")

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("The 6-digit code has been sent to your email address.")
        expect(response.body.token).toBeDefined()

        const decoded = jwt.verify(response.body.token, process.env.JWT_MAIL_SECRET)
        expect(decoded).toHaveProperty("id")
        expect(decoded).toHaveProperty("otpType", "TWO_FACTOR")
    })
})

