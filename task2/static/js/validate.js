//checks if passsword matches confirm password
function confirmPS() {
  const confPass = document.getElementById("conPass").value;
  const pass = document.getElementById("pass").value;

  if (!confPass) {
    alert("Please confirm the password."); // Handles unsupported browsers for `required`
    return false;
  }
  if (pass !== confPass) {
    alert("Passwords do not match.");
    return false;
  }
  return true;
}

//////////////////////////////Use regular expressions/////////////////////////////////////////////////////
//check password strength
function validatePassword() {
  const password = document.getElementById("pass").value;
  const passAlert = document.getElementById("passAlert");
  const validationCriteria = {
    lowerCase: (password.match(/[a-z]/g) || []).length >= 2,
    upperCase: (password.match(/[A-Z]/g) || []).length >= 2,
    numbers: (password.match(/[0-9]/g) || []).length >= 2,
    specialChar: (password.match(/[!@#$%^&*(),.?":{}|<>~`_+\-=\\[\]\/]/g) || []).length >= 2,
  };

  if (!validationCriteria.lowerCase) {
    passAlert.innerHTML = `<span style="color:red">The password must contain at least two lowercase letters.</span>`;
    return false;
  }
  if (!validationCriteria.upperCase) {
    passAlert.innerHTML = `<span style="color:red">The password must contain at least two uppercase letters.</span>`;
    return false;
  }
  if (!validationCriteria.numbers) {
    passAlert.innerHTML = `<span style="color:red">The password must contain at least two numbers.</span>`;
    return false;
  }
  if (!validationCriteria.specialChar) {
    passAlert.innerHTML = `<span style="color:red">The password must contain at least two special characters.</span>`;
    return false;
  }

  // Clear any previous alert and proceed with password confirmation
  passAlert.innerHTML = "";
  return confirmPS();
}
