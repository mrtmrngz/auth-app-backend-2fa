import request from "supertest";
import mongoose from "mongoose";
import User from "../../models/User.model.js";
import app from "../../app.js";
import {generateRefreshToken} from "../../libs/generateTokens.js";

beforeAll(async () => {

    if (mongoose.connection.readyState === 1) {
        await mongoose.disconnect();
    }

    await mongoose.connect(process.env.MONGO_URI_TEST)
})

afterAll(async () => {
    await mongoose.connection.close()
})

describe("Refresh token test", () => {

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

    test("should return 204 if no token is provided", async () => {

        const response = await request(app).get("/api/auth/get-token")

        expect(response.statusCode).toBe(204);
    })

    test("should return 403 if token is invalid", async () => {

        const response = await request(app).get("/api/auth/get-token").set('Cookie', [`_session=invalidtoken`])

        expect(response.statusCode).toBe(403);
        expect(response.body.success).toBe(false);
        expect(response.body.error).toEqual("Invalid Token");
    })

    test("should return 200 and a new accessToken if refresh token is valid", async () => {

        const token = generateRefreshToken("test_id", "USER")

        const response = await request(app).get("/api/auth/get-token").set('Cookie', [`_session=${token}`])

        expect(response.statusCode).toBe(200);
        expect(response.body.success).toBe(true);
        expect(response.body.accessToken).toBeDefined()
    })
})

