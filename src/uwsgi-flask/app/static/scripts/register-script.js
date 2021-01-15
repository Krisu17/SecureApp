document.addEventListener('DOMContentLoaded', function (event) {

    const GET = "GET";
    const POST = "POST";
    const URL = "https://localhost/";

    const NAME_FIELD_ID = "name";
    const SURNAME_FIELD_ID = "surname";
    const BIRTH_DATE_FIELD_ID = "birthDate";
    const EMAIL_FIELD_ID = "email";
    const LOGIN_FIELD_ID = "login";
    const PASSWORD_FIELD_ID = "password";
    const REPEAT_PASSWORD_FIELD_ID = "second_password";
    const SUBMIT_BUTTON_ID = "button-reg-form";
    const ENTROPHY_BAR_ID = "passwordEntropy";
    const ENTROPHY_TEXT_ID = "passwordEntropyText";

    var HTTP_STATUS = {OK: 200, CREATED: 201, BAD_REQUEST: 400, NOT_FOUND: 404};

    prepareEventOnNameChange();
    prepareEventOnSurnameChange();
    prepareEventOnDateChange();
    prepareEventOnEmailChange();
    prepareEventOnLoginChange();
    prepareEventOnPasswordChange();
    prepareEventOnRepeatPasswordChange();

    let registrationForm = document.getElementById("registration-form");

    registrationForm.addEventListener("submit", function (event) {
        event.preventDefault();

        if(isFormOK()) {
            submitRegisterForm();
            setTimeout(function(){
                if (document.getElementById("correctRegister") !== null) {
                    window.location = "/";
                }
            }, 2000);
        }
    });

    function isFormOK() {
        let emptyFieldWarningMessage = "Wszystkie pola są wymagane! Aby przejść dalej proszę wszystkie poprawnie wypełnić.";
        let emptyFieldWaringElemId = "emptyWarning";
        if(isAnyInputEmpty()) {
            showWarningMessage(emptyFieldWaringElemId, emptyFieldWarningMessage, SUBMIT_BUTTON_ID);
            return false;
        } else {
            removeWarningMessage(emptyFieldWaringElemId);
        }
        let nameWarningElemId = document.getElementById("nameWarning");
        let surnameWarningElemId = document.getElementById("surnameWarning");
        let birthDateYearWarningElemId = document.getElementById("yearWarning");
        let emailWarningElemId = document.getElementById("emailWarning");
        let loginAvailabilityWarningElemId = document.getElementById("availableLoginWarning");
        let loginValidityWarningElemId = document.getElementById("validLoginWarning");
        let passwordWarningElemId = document.getElementById("passwordWarning");
        let repeatPasswordWarningElemId = document.getElementById("repeatPasswordWarning");

        

        if( nameWarningElemId === null &&
            surnameWarningElemId === null &&
            birthDateYearWarningElemId === null &&
            loginAvailabilityWarningElemId === null &&
            emailWarningElemId === null &&
            loginValidityWarningElemId === null &&
            passwordWarningElemId === null &&
            repeatPasswordWarningElemId === null) {
            return true;
        } else {
            return false;
        }
    }

    function isAnyInputEmpty() {
        if (
            document.getElementById(NAME_FIELD_ID).value === "" ||
            document.getElementById(SURNAME_FIELD_ID).value === "" ||
            document.getElementById(BIRTH_DATE_FIELD_ID).value === "" ||
            document.getElementById(EMAIL_FIELD_ID).value === "" ||
            document.getElementById(LOGIN_FIELD_ID).value === "" ||
            document.getElementById(PASSWORD_FIELD_ID).value === "" ||
            document.getElementById(REPEAT_PASSWORD_FIELD_ID).value === ""
        ) {
            return true;
        } else {
            return false;
        }
    }


    function prepareEventOnLoginChange() {
        let loginInput = document.getElementById(LOGIN_FIELD_ID);
        loginInput.addEventListener("change", updateLoginAvailabilityMessage);
    }

    function prepareEventOnPasswordChange() {
        let passwordInput = document.getElementById(PASSWORD_FIELD_ID);
        passwordInput.addEventListener("change", updatePasswordValidityMessage);
        passwordInput.addEventListener("change", updateRepeatPasswordValidityMessage);
        passwordInput.addEventListener("input", updateEntrophyStatusBar);
    }

    function prepareEventOnRepeatPasswordChange() {
        let repeatPasswordInput = document.getElementById(REPEAT_PASSWORD_FIELD_ID);
        repeatPasswordInput.addEventListener("change", updateRepeatPasswordValidityMessage);
    }

    function prepareEventOnDateChange() {
        let dateInput = document.getElementById(BIRTH_DATE_FIELD_ID);
        dateInput.addEventListener("change", updateDateValidityMessage);
    }

    function prepareEventOnNameChange() {
        let name = document.getElementById(NAME_FIELD_ID);
        name.addEventListener("change", updateNameValidityMessage);
    }

    function prepareEventOnSurnameChange() {
        let surname = document.getElementById(SURNAME_FIELD_ID);
        surname.addEventListener("change", updateSurnameValidityMessage);
    }

    function prepareEventOnEmailChange() {
        let email = document.getElementById(EMAIL_FIELD_ID);
        email.addEventListener("change", updateEmailValidityMessage);
    }

    function updateLoginAvailabilityMessage() {
        let availabilityWarningElemId = "availableLoginWarning";
        let validityWarningElemId = "validLoginWarning";
        let loginTakenWarningMessage = "Ten login jest już zajęty.";
        let wrongLoginFormatWarningMessage = "Login musi składać się z 5 znaków i zawierać tylko litery."

        isLoginAvailable().then(function (isAvailable) {
            if (isAvailable) {
                removeWarningMessage(availabilityWarningElemId);
            } else {
                showWarningMessage(availabilityWarningElemId, loginTakenWarningMessage, LOGIN_FIELD_ID);
            }
        }).catch(function (error) {
            console.error("Something went wrong while checking login.");
            console.error(error);
        });

        if (isLoginValid() === true) {
            removeWarningMessage(validityWarningElemId);
        } else {
            showWarningMessage(validityWarningElemId, wrongLoginFormatWarningMessage, LOGIN_FIELD_ID)
        }
    }

    function showWarningMessage(newElemId, message, textBoxId) {
        let warningElem = prepareWarningElem(newElemId, message);
        appendAfterElem(textBoxId, warningElem);
    }

    function showSuccesMessage(newElemId, message, textBoxId) {
        let warningElem = prepareWarningElem(newElemId, message);
        warningElem.className = "success-field";
        appendAfterElem(textBoxId, warningElem);
    }

    function removeWarningMessage(warningElemId) {
        let warningElem = document.getElementById(warningElemId);

        if (warningElem !== null) {
            warningElem.remove();
        }
    }

    function prepareWarningElem(newElemId, message) {
        let warningField = document.getElementById(newElemId);

        if (warningField === null) {
            let textMessage = document.createTextNode(message);
            warningField = document.createElement('span');

            warningField.setAttribute("id", newElemId);
            warningField.className = "warning-field";
            warningField.appendChild(textMessage);
        }
        return warningField;
    }

    function appendAfterElem(currentElemId, newElem) {
        let currentElem = document.getElementById(currentElemId);
        currentElem.insertAdjacentElement('afterend', newElem);
    }

    function isLoginAvailable() {
        return Promise.resolve(checkLoginAvailability().then(function (statusCode) {
            if (statusCode === HTTP_STATUS.OK) {
                return false;

            } else if (statusCode === HTTP_STATUS.NOT_FOUND) {
                return true;

            } else {
                throw "Unknown login availability status: " + statusCode;
            }
        }));
    }

    function checkLoginAvailability() {
        let loginInput = document.getElementById(LOGIN_FIELD_ID);
        let baseUrl = URL + "register/";
        let userUrl = baseUrl + loginInput.value;

        return Promise.resolve(fetch(userUrl, {method: GET}).then(function (resp) {
            return resp.status;
        }).catch(function (err) {
            return err.status;
        }));
    }

    function submitRegisterForm() {
        let registerUrl = URL + "register_new_user";
        let csrfToken = document.getElementById("csrf_token");

        let registerParams = {
            method: POST,
            body: new FormData(registrationForm),
            redirect: "follow",
            "X-CSRF-Token": csrfToken
        };

        fetch(registerUrl, registerParams)
            .then(response => getRegisterResponseData(response))
            .then(response => displayInConsoleCorrectResponse(response))
            .catch(err => {
                console.log("Caught error: " + err);
            });
    }

    function getRegisterResponseData(response) {  
        let status = response.status;

        if (status === HTTP_STATUS.OK || status === HTTP_STATUS.CREATED) {
            return response;
        } else {
            console.error("Response status code: " + response.status);
            throw "Unexpected response status: " + response.status;
        }
    }

    function displayInConsoleCorrectResponse(correctResponse) {
        let status = correctResponse.status;
        console.log("status " + status)
        let correctRegisterInfo = "correctRegister";
        let sucessMessage = "Użytkownik został zarejestrowany pomyślnie. Zaraz nastąpi przekierowanie.";
        let warningRegisterInfo = "unsuccessfulRegister";
        let warningMessage = "Podczas rejstracji wystąpił błąd.";

        if (status !== HTTP_STATUS.CREATED) {
            removeWarningMessage(correctRegisterInfo);
            showWarningMessage(warningRegisterInfo, warningMessage, SUBMIT_BUTTON_ID);
            console.log("Errors: " + correctResponse.errors);
        } else {
            removeWarningMessage(warningRegisterInfo);
            showSuccesMessage(correctRegisterInfo, sucessMessage, SUBMIT_BUTTON_ID);
        }
    }


    function updatePasswordValidityMessage() {
        let warningElemId = "passwordWarning";
        let warningMessage = "Co najmniej 8 znaków(do 32), mała i duża litera oraz znak specjalny.";

        if (isPasswordValid() === true) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, PASSWORD_FIELD_ID);
        }
    }

    function isPasswordValid() {
        let regExpression = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#\$%\^&\*]).{8,32}$/;
        let password = document.getElementById(PASSWORD_FIELD_ID);
        if (password.value.match(regExpression)) {
            return true;
        } else {
            return false;
        }
    }

    function updateRepeatPasswordValidityMessage() {
        let warningElemId = "repeatPasswordWarning";
        let warningMessage = "Hasła nie są identyczne!";

        if (arePasswordsTheSame() === true) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, REPEAT_PASSWORD_FIELD_ID);
        }
    }

    function arePasswordsTheSame() {
        let password = document.getElementById(PASSWORD_FIELD_ID);
        let repeatPassword = document.getElementById(REPEAT_PASSWORD_FIELD_ID);

        if (password.value === repeatPassword.value) {
            return true;
        } else {
            return false;
        }
    }

    function isLoginValid() {
        let regExpression = /^[A-Za-z]{5,32}$/;
        let login = document.getElementById(LOGIN_FIELD_ID);
        if (login.value.match(regExpression) && login.value.length > 4) {
            return true;
        } else {
            return false;
        }
    }

    function updateDateValidityMessage() {
        let warningYearElemId = "yearWarning";
        let warningYearMessage = "Podany rok nie jest prawidłowy. Musi zawierać się od 1900 do roku obecnego.";
        let warningDateElemId = "dateWarning";

        if (document.getElementById(BIRTH_DATE_FIELD_ID).value !== undefined){
            removeWarningMessage(warningDateElemId);
        }
        let birthDate = new Date(document.getElementById(BIRTH_DATE_FIELD_ID).value);
        year = birthDate.getFullYear();
    
        if (year > 1900 && year < new Date().getFullYear()) {
            removeWarningMessage(warningYearElemId);
        } else {
            showWarningMessage(warningYearElemId, warningYearMessage, BIRTH_DATE_FIELD_ID);
        }
    }


    function updateNameValidityMessage() {
        let warningElemId = "nameWarning";
        let warningMessage = "To pole nie może być puste i musi składać się wyłącznie z liter.";
        let name = document.getElementById(NAME_FIELD_ID).value;
        let regExpression = /^[A-Za-ząćęłńóśźżĄĘŁŃÓŚŹŻ]{1,32}$/;

        if (name.match(regExpression)) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, NAME_FIELD_ID);
        }
    }

    function updateSurnameValidityMessage() {
        let warningElemId = "surnameWarning";
        let warningMessage = "To pole nie może być puste i musi składać się wyłącznie z liter.";
        let surname = document.getElementById(SURNAME_FIELD_ID).value;
        let regExpression = /^[A-Za-ząćęłńóśźżĄĘŁŃÓŚŹŻ]{1,32}$/;

        if (surname.match(regExpression)) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, SURNAME_FIELD_ID);
        }
    }

    function updateEmailValidityMessage() {
        let warningElemId = "emailWarning";
        let warningMessage = "Proszę podać poprawny adres email.";
        let email = document.getElementById(EMAIL_FIELD_ID).value;
        let regExpression = /^[a-z0-9A-Z]+[\._]?[a-z0-9A-Z]+[@]\w+[.]\w{2,3}$/;
        // let regExpression = /\S+@\S+\.\S+/;

        if (email.match(regExpression)) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, EMAIL_FIELD_ID);
        }
    }

    function updateEntrophyStatusBar() {
        let password = document.getElementById(PASSWORD_FIELD_ID).value;
        score = returnEntrophyScore(password);
        if (score < 2.1 ){
            veryLowEntrophy();
        } else if (score < 2.6) {
            lowEntrophy();
        } else if (score < 3.4) {
            middleEntrophy();
        } else {
            highEntrophy();
        }
    }

    function returnEntrophyScore(pass) {
        var H = 0.0;
        var letters = new Object();
        for (var i=0; i<pass.length; i++) {
            letters[pass[i]] = (letters[pass[i]] || 0) + 1;
        }
        
        for (letter in letters) {
            var pi = letters[letter]/pass.length;
            H -= pi*Math.log2(pi)
        }
        return H;
    }

    function veryLowEntrophy() {
        var bar = document.getElementById(ENTROPHY_BAR_ID);
        var text = document.getElementById(ENTROPHY_TEXT_ID);
        bar.style.width = "1%";
        bar.style.backgroundColor = "red";
        text.innerHTML = ("<h5>Bardzo mała</h5>");
    }

    function lowEntrophy() {
        var bar = document.getElementById(ENTROPHY_BAR_ID);
        var text = document.getElementById(ENTROPHY_TEXT_ID);
        bar.style.width = "20%";
        bar.style.backgroundColor = "orange";
        text.innerHTML = ("<h5>Mała</h5>");
    }

    function middleEntrophy() {
        var bar = document.getElementById(ENTROPHY_BAR_ID);
        var text = document.getElementById(ENTROPHY_TEXT_ID);
        bar.style.width = "50%";
        bar.style.backgroundColor = "yellow";
        text.innerHTML = ("<h5>Średnia</h5>");
    }

    function highEntrophy() {
        var bar = document.getElementById(ENTROPHY_BAR_ID);
        var text = document.getElementById(ENTROPHY_TEXT_ID);
        bar.style.width = "90%";
        bar.style.backgroundColor = "green";
        text.innerHTML = ("<h5>Duża</h5>");
    }

});