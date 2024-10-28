"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const dotenv_1 = __importDefault(require("dotenv"));
const bcrypt_1 = __importDefault(require("bcrypt"));
const mongoose_1 = __importDefault(require("mongoose"));
const user_schema_1 = require("./models/user.schema");
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const cookie_parser_1 = __importDefault(require("cookie-parser"));
const auth_schema_1 = require("./models/auth.schema");
dotenv_1.default.config();
console.log(process.env.MONGO_URI);
mongoose_1.default
    .connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 60000, // Increase timeout
})
    .then(() => console.log("mongodb connection success"))
    .catch((error) => console.log(error));
const app = (0, express_1.default)();
app.use(express_1.default.json());
app.use((0, cookie_parser_1.default)());
app.post("/register", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { name, email, password } = req.body;
    console.time("Hashed");
    const hashedPassword = yield bcrypt_1.default.hash(password, 10);
    console.timeEnd("Hashed");
    // payload /data yg akan di transfer
    const newUser = {
        name,
        email,
        password: hashedPassword,
    };
    const createUser = new user_schema_1.User(newUser);
    const data = yield createUser.save();
    return res.json({ message: "user register success", data });
}));
app.post("/login", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { email, password } = req.body;
    if (!email || password.length < 4) {
        return res.json({
            message: "Email should be valid and password should have minimum 8 characters",
        });
    }
    const user = yield user_schema_1.User.findOne({ email });
    if (!user) {
        return res
            .status(403)
            .json({ message: "Invalid credentials :user not found" });
    }
    const isPasswordMatch = yield bcrypt_1.default.compare(password, user.password);
    if (!isPasswordMatch) {
        return res
            .status(403)
            .json({ message: "Invalid credentials :invalid password" });
    }
    //auth strategy JWS/SESSION
    const payload = {
        id: user.id,
        name: user.name,
        email: user.email,
    };
    const accesToken = jsonwebtoken_1.default.sign(payload, process.env.JWT_ACCESS_SECRET, {
        expiresIn: 300,
    });
    const refreshToken = jsonwebtoken_1.default.sign(payload, process.env.JWT_REFRESH_SECRET, {
        expiresIn: "7d",
    });
    const newRefreshToken = new auth_schema_1.Auth({
        userId: user.id,
        refreshToken,
    });
    newRefreshToken.save();
    return res
        .cookie("accessToken", accesToken, { httpOnly: true })
        .cookie("refreshToken", refreshToken, { httpOnly: true })
        .status(200)
        .json({ message: "login success !" });
}));
app.post("/logout", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { refreshToken } = req.cookies;
    yield auth_schema_1.Auth.findOneAndDelete({ refreshToken });
    return res
        .clearCookie("accessToken")
        .clearCookie("refreshToken")
        .status(200)
        .json({ message: "sudah berhasil keluar" });
}));
//RESOURCE ENDPOINT
app.get("/resources", (req, res) => __awaiter(void 0, void 0, void 0, function* () {
    const { accessToken, refreshToken } = req.cookies;
    //check accessToken refreshToken
    if (!accessToken && !refreshToken) {
        console.log("accessToken & refreshToken invalid");
        return res
            .status(401)
            .json({ message: "Unauthorized, please login first !" });
    }
    if (accessToken) {
        try {
            jsonwebtoken_1.default.verify(accessToken, process.env.JWT_ACCESS_SECRET);
            console.log("access token valid");
            return res.status(200).json({ message: "Ini datanya" });
        }
        catch (error) {
            try {
                console.log("verification proccess refresh token");
                jsonwebtoken_1.default.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
                console.log("check refreshToken on DB");
                const activeRefreshToken = yield auth_schema_1.Auth.findOne({
                    refreshToken: refreshToken,
                });
                if (!activeRefreshToken) {
                    console.log("Refresh token not found on DB");
                    return res.status(401).json({ message: "please re-login" });
                }
                const payload = jsonwebtoken_1.default.decode(refreshToken);
                console.log("create new Access token");
                const newAccessToken = jsonwebtoken_1.default.sign({
                    id: payload === null || payload === void 0 ? void 0 : payload.id,
                    name: payload.name,
                    email: payload.email,
                }, process.env.JWT_ACCESS_SECRET, { expiresIn: 300 });
                return res
                    .cookie("accessToken", newAccessToken, { httpOnly: true })
                    .json({ message: "ini datanya" });
            }
            catch (error) {
                console.log(error);
            }
        }
    }
}));
app.listen(process.env.PORT, () => {
    console.log(`process running at port: ${process.env.PORT}`);
});
