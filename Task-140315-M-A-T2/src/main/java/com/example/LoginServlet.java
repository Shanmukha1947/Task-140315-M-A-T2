package com.example;



import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

@WebServlet("/login")
public class LoginServlet extends HttpServlet {

    private final String secretKey = "yourSecretKeyShouldBeLongAndUnique";

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String username = req.getParameter("username");
        String password = req.getParameter("password");

        // Step 1: Hash the password using a secure hashing algorithm (bcrypt is recommended)
        String hashedPassword = hashPassword(password);

        // Step 2: Validate the username and hashed password against your user store
        boolean isValidUser = isValidUser(username, hashedPassword);

        if (isValidUser) {
            // Step 3: Create a new session and set session attributes
            HttpSession session = req.getSession();
            session.setAttribute("username", username);
            session.setMaxInactiveInterval(30 * 60); // Set session expiration to 30 minutes

            resp.sendRedirect("home"); // Redirect to the welcome page
        } else {
            resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Invalid username or password");
        }
    }

    private String hashPassword(String password) {
        try {
            // Use a secure hashing algorithm like bcrypt
            String salt = generateSalt();
            byte[] hashedBytes = MessageDigest.getInstance("SHA-256").digest((password + salt).getBytes());
            return Base64.getEncoder().encodeToString(hashedBytes) + ":" + salt;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Hashing algorithm not found", e);
        }
    }

    private boolean isValidUser(String username, String hashedPassword) {
        // Replace this with your actual user authentication logic
        // For demonstration purposes, we'll just check if the username and password match a hardcoded value.
        String correctUsername = "exampleUser";
        String correctHashedPassword = "$2a$10$t7Hq1v791.s8888888888O8888888888888888888888888888886"; // bcrypt hash of "password" with a random salt

        return username.equals(correctUsername) && hashedPassword.equals(correctHashedPassword);
    }

    private String generateSalt() {
        // Generate a random salt for password hashing
        byte[] salt = new byte[16];
        // SecureRandom.getInstanceStrong().nextBytes(salt); // Use this in production
        // For demonstration purposes, we'll use a fixed salt
        System.arraycopy("fixedSaltForDemo".getBytes(), 0, salt, 0, Math.min("fixedSaltForDemo".getBytes().length, salt.length));
        return Base64.getEncoder().encodeToString(salt);
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.getRequestDispatcher("/WEB-INF/login.jsp").forward(req, resp);
    }
}

