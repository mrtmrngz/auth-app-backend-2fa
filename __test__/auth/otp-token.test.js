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

        expect(response.statusCode).toBe(410);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Too many failed attempts. Your account has been deleted. Please register again.")
        expect(response.body.code).toEqual("ACCOUNT_DELETED")
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

        expect(response.statusCode).toBe(423);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Too many failed attempts. Your account has been locked. Please try again later")
        expect(response.body.code).toEqual("ACCOUNT_LOCKED")
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
        expect(response.body.code).toEqual("LOGIN_SUCCESS")
        expect(response.body.accessToken).toBeDefined()

        const refresh_token_session_cookie = response.headers["set-cookie"].find(cookie => cookie.startsWith("_session="))
        expect(refresh_token_session_cookie).toBeDefined()
        expect(refresh_token_session_cookie).toContain("HttpOnly")

        const decoded = jwt.verify(response.body.accessToken, process.env.JWT_ACCESS_SECRET)
        expect(decoded).toHaveProperty("id")
        expect(decoded).toHaveProperty("role")
    })

    // EMAIL CHANGE

    test("If the email OTP code is entered incorrectly 5 times, the user should be locked for 10 minutes.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            newEmail: "newtestuser@mail.com",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "EMAIL_CHANGE",
            otpAttemps: 4
        });

        const token = generateMailToken("EMAIL_CHANGE", test_user._id)

        const data = {
            token,
            otp: "123451",
            otpType: "EMAIL_CHANGE"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(423);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Too many failed attempts. Your email change request has been locked. Please try again in 10 minutes.")
        expect(response.body.code).toEqual("ACCOUNT_LOCKED")
    })

    test("Email should be successfully changed when the correct OTP is entered", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            newEmail: "newtestuser@mail.com",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "EMAIL_CHANGE",
        });

        const token = generateMailToken("EMAIL_CHANGE", test_user._id)

        const data = {
            token,
            otp: "123456",
            otpType: "EMAIL_CHANGE"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("User Email Address changed successfully")
    })

    // USERNAME CHANGE

    test("If the email OTP code is entered incorrectly 5 times, the user should be locked for 10 minutes.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            newUsername: "changetestusername",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "USERNAME_CHANGE",
            otpAttemps: 4
        });

        const token = generateMailToken("USERNAME_CHANGE", test_user._id)

        const data = {
            token,
            otp: "123451",
            otpType: "USERNAME_CHANGE"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(423);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Too many failed attempts. Your username change request has been locked. Please try again in 10 minutes.")
        expect(response.body.code).toEqual("ACCOUNT_LOCKED")
    })

    test("Username should be successfully changed when the correct OTP is entered", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            newUsername: "changetestusername",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "USERNAME_CHANGE",
        });

        const token = generateMailToken("USERNAME_CHANGE", test_user._id)

        const data = {
            token,
            otp: "123456",
            otpType: "USERNAME_CHANGE"
        }

        const response = await request(app).post("/api/auth/verify-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(200);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("User username changed successfully")
    })

    // RESEND TOKEN TESTS

    test("If there is no token, it should fail.", async () => {
        const data = {
            otpType: "VERIFY_ACCOUNT",
        }

        const response = await request(app).post("/api/auth/resend-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(400)
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Token are required")
    })

    test("If there is no otp type, it should fail.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "VERIFY_ACCOUNT",
        });

        const token = generateMailToken("VERIFY_ACCOUNT", test_user._id)

        const data = {
            token: token,
        }

        const response = await request(app).post("/api/auth/resend-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(400)
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("OTP type is required")
    })

    test("If the token decode fails, it should give a failed result.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "VERIFY_ACCOUNT",
        });

        const data = {
            token: "token",
            otpType: "VERIFY_ACCOUNT"
        }

        const response = await request(app).post("/api/auth/resend-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(401)
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Invalid or corrupted token.")
    })

    test("If an invalid OTP type is entered, it should return a failure result.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "VERIFY_ACCOUNT",
        });

        const token = generateMailToken("VERIFY_ACCOUNT", test_user._id)

        const data = {
            token: token,
            otpType: "INVALID_T0KEN"
        }

        const response = await request(app).post("/api/auth/resend-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(403)
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Invalid OTP type")
    })

    test("If the OTP type is 2FA and the user is locked and the account unlock time has not come, it should return a failed result.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            isUserLocked: true,
            userLockExpire: new Date(Date.now() + (1000 * 60 * 60 * 60)),
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "TWO_FACTOR",
        });

        const token = generateMailToken("TWO_FACTOR", test_user._id)

        const data = {
            token: token,
            otpType: "TWO_FACTOR"
        }

        const response = await request(app).post("/api/auth/resend-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(423)
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toMatch(/Your account is locked please try/)
    })

    test("If everything is OK, a successful result will be returned and the OTP code will be sent to the user email address again, and the client will receive the token again.", async () => {

        const hashedPassword = await bcrypt.hash("test123", 10)

        const test_user = await User.create({
            email: "testuser@mail.com",
            username: "testuser",
            password: hashedPassword,
            isVerified: true,
            otp: "123456",
            otpExpire: new Date(Date.now() + (1000 * 60 * 5)),
            otpType: "VERIFY_ACCOUNT",
        });

        const token = generateMailToken("VERIFY_ACCOUNT", test_user._id)

        const data = {
            token: token,
            otpType: "VERIFY_ACCOUNT"
        }

        const response = await request(app).post("/api/auth/resend-otp").send(data).set("Accept", "application/json")

        expect(response.statusCode).toBe(200)
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("The code has been sent to your email address")
        expect(response.body.token).toBeDefined()

        const decoded = jwt.verify(response.body.token, process.env.JWT_MAIL_SECRET)

        expect(decoded).toHaveProperty('id')
        expect(decoded).toHaveProperty('otpType', "VERIFY_ACCOUNT")
    })
})

