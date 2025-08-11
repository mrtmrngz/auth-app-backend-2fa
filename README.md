# NODEJS 2FA AUTH APP BACKEND

techs: express, mongoose, nodemon, nodemailer, jwt, express-rate-limit

özellikler: role based auth, token ile parola sıfırlama, otp ile verify email ve 2fa, 2fa var, ilgili alanlar (otp, reset password nodemailer ile maile gönderilicek), username ve email sıfırlama, eğer email verify otp 5kere yanlış girilirse hesap silinicek eğer 2fa otp 5 kere yanlış girilirse hesap 10dk kilitlenicek ve daha fazla otp girişine izin vermeyecek 10dk sonra tekrar deneyebilir. Multer cloudinary avatar yükleme var. Admin dashboard (haftalık kayıtlı kullancılar, en son kayıt olan kullanıcılar, banlı kullanıcılar), ban ekleme,kaldırma