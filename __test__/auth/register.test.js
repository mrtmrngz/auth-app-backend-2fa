import request from "supertest";
import mongoose from "mongoose";
import User from "../../models/User.model.js";
import app from "../../app.js";
import jwt from 'jsonwebtoken'
import {generateMailToken} from "../../libs/generateTokens.js";

beforeAll(async () => {

    if (mongoose.connection.readyState === 1) {
        await mongoose.disconnect();
    }

    await mongoose.connect(process.env.MONGO_URI_TEST)
})

afterAll(async () => {
    await mongoose.connection.close()
})

describe("Register test", () => {

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

    test("A new user must be registered successfully", async () => {
        const newUser = {
            username: `test_user_${Date.now()}`,
            email: `testuser${Date.now()}@test.com`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/register").send(newUser).set("Accept", "application/json")

        expect(response.statusCode).toBe(201);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(true)
        expect(response.body.message).toEqual("Register successful please check your email!")
        expect(response.body.token).toBeDefined()

        const decoded = await jwt.verify(response.body.token, process.env.JWT_MAIL_SECRET)
        expect(decoded).toHaveProperty('id')
        expect(decoded).toHaveProperty('otpType', 'VERIFY_ACCOUNT')
    })

    test("Registration attempt with incomplete information must fail (empty email)", async () => {
        const newUser = {
            username: `test_user_${Date.now()}`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/register").send(newUser).set("Accept", "application/json")

        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Email cannot be empty")
    })

    test("Registration attempt with incomplete information must fail (username email)", async () => {
        const newUser = {
            email: `testuser${Date.now()}@test.com`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/register").send(newUser).set("Accept", "application/json")

        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("Username cannot be empty")
    })

    test("Existing user error test", async () => {

        await User.create({
            email: "existinguser@test.com",
            username: "existingusertest",
            password: "test123",
            isVerified: true
        });

        const newUser = {
            username: `existingusertest`,
            email: `existinguser@test.com`,
            password: "test123"
        }

        const response = await request(app).post("/api/auth/register").send(newUser).set("Accept", "application/json")

        expect(response.statusCode).toBe(400);
        expect(response.headers['content-type']).toMatch(/json/);
        expect(response.body.success).toBe(false)
        expect(response.body.error).toEqual("User already exist!")
    })
})

