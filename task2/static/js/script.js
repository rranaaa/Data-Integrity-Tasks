// Password visibility toggle function
function togglePassword(inputId, button) {
    const passwordField = document.getElementById(inputId);
    const icon = button.querySelector("i");

    if (passwordField.type === "password") {
        passwordField.type = "text";
        icon.classList.remove("fa-eye");
        icon.classList.add("fa-eye-slash");
    } else {
        passwordField.type = "password";
        icon.classList.remove("fa-eye-slash");
        icon.classList.add("fa-eye");
    }
}

// Password validation based on the policy
function validatePassword(password) {
  const validationCriteria = {
    lowerCase: (password.match(/[a-z]/g) || []).length >= 1,
    upperCase: (password.match(/[A-Z]/g) || []).length >= 1,
    numbers: (password.match(/[0-9]/g) || []).length >= 1,
    specialChar: (password.match(/[!@#$%^&*(),.?":{}|<>~`_+\-=\\[\]\/]/g) || []).length >= 1,
  }

  return validationCriteria.lowerCase && validationCriteria.upperCase && validationCriteria.numbers && validationCriteria.specialChar;
}

// Email validation regex
function validateEmail(email) {
    const emailRegex = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}$/;
    return emailRegex.test(email);
}

// Form submission handler for validation
document.getElementById('signupFormElement').addEventListener('submit', function(event) {
    const emailField = document.getElementById('email');
    const passwordField = document.getElementById('passwordSignup');
    const usernameField = document.getElementById('username');

    const passwordValid = validatePassword(passwordField.value);
    const emailValid = validateEmail(emailField.value);
    const fieldsFilled = usernameField.value && emailField.value && passwordField.value;

    // Check if the email is already used (simulate backend check)
    if (emailField.value === "alreadyused@example.com") {
        alert("Email is already in use! Please choose another one.");
        event.preventDefault(); // Prevent form submission
        return;
    }

    // Validate password
    if (!passwordValid) {
        alert("Password must be at least 8 characters long, include an uppercase letter, a lowercase letter, a number, and a special character.");
        event.preventDefault();
        return;
    }

    // Validate email format
    if (!emailValid) {
        alert("Please enter a valid email address.");
        event.preventDefault();
        return;
    }

    // Validate if all fields are filled
    if (!fieldsFilled) {
        alert("Please fill in all fields.");
        event.preventDefault();
        return;
    }
});
