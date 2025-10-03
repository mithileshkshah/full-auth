export const forgotPasswordMail = (resetUrl: string, username: string) => `
  <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Password Reset</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            background: #f4f4f4;
            margin: 0;
            padding: 0;
          }
          .container {
            max-width: 600px;
            margin: 20px auto;
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 6px rgba(0, 0, 0, 0.1);
          }
          .header {
            background: #0d6efd;
            color: #fff;
            padding: 20px;
            text-align: center;
          }
          .content {
            padding: 20px;
            color: #333;
          }
          .footer {
            font-size: 12px;
            color: #777;
            text-align: center;
            padding: 15px;
            background: #f9f9f9;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h2>Password Reset Request</h2>
          </div>
          <div class="content">
            <p>Hi <b>${username}</b>,</p>
            <p>
              You requested to reset your password. Please click the button below to
              continue:
            </p>
            <p style="text-align: center">
              <a
                href="${resetUrl}"
                style="
                  display: inline-block;
                  padding: 12px 20px;
                  margin: 20px 0;
                  background-color: #0d6efd;
                  color: #ffffff !important;
                  text-decoration: none;
                  border-radius: 5px;
                  font-weight: bold;
                "
              >
                Reset Password
              </a>
            </p>
            <p>If you did not request this, you can safely ignore this email.</p>
          </div>
          <div class="footer">
            <p>
              © ${new Date().getFullYear()} Full Auth Implementation. All rights
              reserved.
            </p>
          </div>
        </div>
      </body>
    </html>
`;
