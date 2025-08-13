import request from "supertest";
import mongoose from "mongoose";
import User from "../../models/User.model.js";
import app from "../../app.js";
import {generateAccessToken} from "../../libs/generateTokens.js";

beforeAll(async () => {

    if (mongoose.connection.readyState === 1) {
        await mongoose.disconnect();
    }

    await mongoose.connect(process.env.MONGO_URI_TEST)
})

afterAll(async () => {
    await mongoose.connection.close()
})

describe("Logout test", () => {

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

    test("should return 401 if no token is provided", async () => {

        const response = await request(app).post("/api/auth/logout")

        expect(response.statusCode).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("No logged in user")
    })

    test("should return 401 if token is invalid", async () => {

        const response = await request(app).post("/api/auth/logout").set('Authorization', "Bearer invalid_token")

        expect(response.statusCode).toBe(401);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("No logged in user")
    })

    test("should return 200 and clear cookie if token is valid", async () => {

        const token = generateAccessToken("test_id", "USER")

        const response = await request(app).post("/api/auth/logout").set('Authorization', `Bearer ${token}`)

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.message).toEqual("Logout Successful.")

        const cookies = response.headers["set-cookie"]
        expect(cookies.some(c => c.startsWith("_session=;"))).toBe(true)
    })
})

