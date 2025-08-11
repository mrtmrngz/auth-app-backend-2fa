export const OTP_TEMPLATE = `
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{email content}}</title>
</head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 50px 0; background-color: #f4f4f4;">
    <div style="max-width: 600px; margin: 20px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
        
        <div style="text-align: center; padding-bottom: 20px; padding-top: 20px; border-bottom: 1px solid #eeeeee;">
            <h1 style="color: #333333; font-size: 24px; margin: 0;">NODEJS AUTH APP</h1>
        </div>
        
        <div style="padding: 20px 0; text-align: center;">
            <h2 style="color: #555555; font-size: 20px;">Verify Your Email Address</h2>
            <p style="color: #666666; line-height: 1.5; font-size: 16px;">
                Hello,
                <br><br>
                To complete your sign-up or login, please use the following one-time verification code. This code is valid for 5 minutes.
            </p>
            
            <div style="background-color: #f0f0f0; border: 1px solid #e0e0e0; border-radius: 5px; padding: 15px 25px; margin: 25px 0; display: inline-block;">
                <p style="color: #333333; font-size: 32px; font-weight: bold; letter-spacing: 5px; margin: 0;">{{ otp_code }}</p>
            </div>
            
            <p style="color: #666666; font-size: 14px;">
                If you did not request this, you can safely ignore this email.
            </p>
        </div>
        
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #eeeeee; font-size: 12px; color: #aaaaaa;">
            <p>&copy; 2025 NODEJS AUTH APP. All rights reserved.</p>
        </div>
        
    </div>
</body>
</html>
`

export const RESET_PASSWORD_MAIL = `
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
</head>
<body style="font-family: Arial, sans-serif; margin: 0; padding: 50px 0; background-color: #f4f4f4;">
    <div style="max-width: 600px; margin: 20px auto; padding: 20px; background-color: #ffffff; border-radius: 8px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);">
        
        <div style="text-align: center; padding-bottom: 20px; padding-top: 20px; border-bottom: 1px solid #eeeeee;">
            <h1 style="color: #333333; font-size: 24px; margin: 0;">NODEJS AUTH APP</h1>
        </div>
        
        <div style="padding: 20px 0; text-align: center;">
            <h2 style="color: #555555; font-size: 20px;">Reset Your Password</h2>
            <p style="color: #666666; line-height: 1.5; font-size: 16px;">
                Hello,
                <br><br>
                We received a request to reset your password. To reset your password, please click the button below. This link is valid for 1 hour.
            </p>
            
            <a href="{{ reset_password_link }}" style="display: inline-block; background-color: #007bff; color: #ffffff; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 25px 0;">
                Reset Password
            </a>
            
            <p style="color: #666666; font-size: 14px;">
                If you did not request this, you can safely ignore this email.
            </p>
        </div>
        
        <div style="text-align: center; padding-top: 20px; border-top: 1px solid #eeeeee; font-size: 12px; color: #aaaaaa;">
            <p>&copy; 2025 NODEJS AUTH APP. All rights reserved.</p>
        </div>
        
    </div>
</body>
</html>

`