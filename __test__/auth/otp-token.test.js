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

describe("OTP token test", () => {

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

    // Verify Mail TEST

    test("User email verification must be successful", async () => {

        const user = await User.create({
            email: "existinguser1@test.com",
            username: "existingusertest1",
            password: "test123",
            otp: "123456",
            otpType: "VERIFY_ACCOUNT",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
        });

        const token = generateMailToken("VERIFY_ACCOUNT", user._id)

        const data = {
            otp: "123456",
            token,
            otpType: "VERIFY_ACCOUNT"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("Email verified, please login!")
    })

    test("If the user email address is verified, it should return a warning.", async () => {

        const user = await User.create({
            email: "existinguser1@test.com",
            username: "existingusertest1",
            password: "test123",
            otp: "123456",
            isVerified: true,
            otpType: "VERIFY_ACCOUNT",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
        });

        const token = generateMailToken("VERIFY_ACCOUNT", user._id)

        const data = {
            otp: "123456",
            token,
            otpType: "VERIFY_ACCOUNT"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.message).toEqual("User already verified")
    })

    test("In email verification, the wrong token type should be entered and a failed result should be obtained.", async () => {

        const user = await User.create({
            email: "existinguser1@test.com",
            username: "existingusertest1",
            password: "test123",
            otp: "123456",
            otpType: "VERIFY_ACCOUNT",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
        });

        const token = generateMailToken("VERIFY_ACCOUNT", user._id)

        const data = {
            otp: "123456",
            token,
            otpType: "VERIFY_ACCOUNTT"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(403);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Unauthorized OTP type")
    })

    test("Entering the wrong code should result in failure", async () => {

        const user = await User.create({
            email: "existinguser1@test.com",
            username: "existingusertest1",
            password: "test123",
            otp: "123456",
            otpType: "VERIFY_ACCOUNT",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
        });

        const token = generateMailToken("VERIFY_ACCOUNT", user._id)

        const data = {
            otp: "1234561",
            token,
            otpType: "VERIFY_ACCOUNT"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Invalid Code")
    })

    test("The user will be deleted because the wrong token was entered for the fifth time.", async () => {

        const user = await User.create({
            email: "existinguser1@test.com",
            username: "existingusertest1",
            password: "test123",
            otp: "123456",
            otpType: "VERIFY_ACCOUNT",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpAttemps: 4
        });

        const token = generateMailToken("VERIFY_ACCOUNT", user._id)

        const data = {
            otp: "1234561",
            token,
            otpType: "VERIFY_ACCOUNT"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(403);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Too many failed attempts. Your account has been deleted. Please register again.")
    })

    test("Verify token attempt with incomplete information must fail.", async () => {

        const user = await User.create({
            email: "existinguser1@test.com",
            username: "existingusertest1",
            password: "test123",
            otp: "123456",
            otpType: "VERIFY_ACCOUNT",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpAttemps: 4
        });

        const token = generateMailToken("VERIFY_ACCOUNT", user._id)

        const data = {
            token,
            otpType: "VERIFY_ACCOUNT"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("OTP and Token are required")
    })

    // 2FA TOKEN

    test("If an incorrect 2FA code is entered 5 times, the user should be locked and send an unsuccessful request.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testmail",
            password: hashedPassword,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "TWO_FACTOR",
            otpAttemps: 4
        });

        const token = generateMailToken("TWO_FACTOR", test_user._id)

        const data = {
            token,
            otp: "123451",
            otpType: "TWO_FACTOR"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(429);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Too many failed attempts. Your account has been locked. Please try again later")
    })

    test("If the user wants to open 2FA and the email is verified, a successful result should be returned.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testmail",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "TWO_FACTOR",
        });

        const token = generateMailToken("TWO_FACTOR", test_user._id)

        const data = {
            token,
            otp: "123456",
            otpType: "TWO_FACTOR"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("2FA activated")
    })

    test("Should return access token after successful 2FA verification", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testmail",
            password: hashedPassword,
            isVerified: true,
            isTwoFactorEnabled: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "TWO_FACTOR",
        });

        const token = generateMailToken("TWO_FACTOR", test_user._id)

        const data = {
            token,
            otp: "123456",
            otpType: "TWO_FACTOR"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

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

    // EMAIL CHANGE
})

