document.addEventListener('DOMContentLoaded', function (event) {
    const CHECKBOX_ID = "secure_checkbox";
    

});


const PASSWORD_FIELD_ID =  "password_input";
function updatePasswordVisibility(checkboxElem) {
    isChecked = checkboxElem.checked
    let passwordField = document.getElementById(PASSWORD_FIELD_ID)
    if(isChecked) {
        passwordField.style.display = ""
    } else {
        passwordField.style.display = "none"
    }
}