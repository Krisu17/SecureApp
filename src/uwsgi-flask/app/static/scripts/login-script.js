
document.addEventListener('DOMContentLoaded', function (event) {

    const GET = "GET";
    const POST = "POST";
    const URL = "https://localhost/";

    const LOGIN_FIELD_ID = "login";
    const PASSWORD_FIELD_ID = "password";
    const LOGIN_BUTTON_ID = "button-log-form"
    var HTTP_STATUS = {OK: 200, FORBIDDEN: 403, NOT_FOUND: 404};

    prepareEventOnLoginChange();
    prepareEventOnPasswordChange();

    let loginForm = document.getElementById("login-form");

    loginForm.addEventListener("submit", function (event) {
        event.preventDefault();
        changeButtonStatus();
        ifFormOkTryLogIn();
        changeButtonStatus();
    });


    function prepareEventOnLoginChange() {
        let loginInput = document.getElementById(LOGIN_FIELD_ID);
        loginInput.addEventListener("change", updateLoginAvailabilityMessage);
    }
    
    function prepareEventOnPasswordChange() {
        let passwordInput = document.getElementById(PASSWORD_FIELD_ID);
        passwordInput.addEventListener("change", updatePasswordValidityMessage);
    }

    const tryLogIn = async () => {
        let loginUrl = URL + "login_user";
        let csrfToken = document.getElementById("csrf_token");

        let loginParams = {
            method: POST,
            body: new FormData(loginForm),
            redirect: "follow",
            "X-CSRF-Token": csrfToken
        };

        let res = await fetch (loginUrl, loginParams);
        displayInConsoleCorrectResponse(res);
        return await res;

    }


    const ifFormOkTryLogIn = async() => {
        
        let warningLoginInfoElemId = "unsuccessfulLogin";
        let warningMessage = "Nieprawidłowy login lub hasło.";
        let blockedInfo = "ipBlocked";
        if(isAnyEmptyImput()) {
            showWarningMessage(warningLoginInfoElemId, warningMessage, LOGIN_BUTTON_ID);
            return false;
        }

        removeWarningMessage(warningLoginInfoElemId);
        removeWarningMessage(blockedInfo);
        let validityWarningElemId = document.getElementById("unsuccessfulLogin");
        let passwordWarningElemId = document.getElementById("passwordWarning");
        
        if( validityWarningElemId === null &&
            passwordWarningElemId === null) {
                try{
                    let res = await tryLogIn();
                    setTimeout(function(){
                        if (document.getElementById("correctLogin") !== null) {
                             window.location = "/";
                        }
                    }, 1000);
                } catch (err) {
                    console.log("Blad podczas logowania");
                }
        } else {
            return false;
        }
    }

    function isAnyEmptyImput() {
        if(
            document.getElementById(LOGIN_FIELD_ID).value === "" ||
            document.getElementById(PASSWORD_FIELD_ID).value === "" 
        ) {
            return true;
        } else {
            return false;
        }
    }

    function displayInConsoleCorrectResponse(correctResponse) {
        let status = correctResponse.status;
        console.log("status " + status)
        let correctLoginInfo = "correctLogin";
        let sucessMessage = "Użytkownik został zalogowany pomyślnie. Za chwilę nastąpi przekierowanie.";
        let warningLoginInfo = "unsuccessfulLogin";
        let warningMessage = "Nieprawidłowy login lub hasło.";
        let blockedInfo = "ipBlocked";
        let blockedMessage = "Zbyt wiele nieudany prób. Twój adres IP został zablokowany. Spróbuj ponownie wkrótce."

        if (status !== HTTP_STATUS.OK) {
            removeWarningMessage(correctLoginInfo);
            if(status === HTTP_STATUS.FORBIDDEN) {
                showWarningMessage(blockedInfo, blockedMessage, LOGIN_BUTTON_ID);
            } else {
                showWarningMessage(warningLoginInfo, warningMessage, LOGIN_BUTTON_ID);
            }
        } else {
            removeWarningMessage(warningLoginInfo);
            removeWarningMessage(blockedInfo);
            showSuccesMessage(correctLoginInfo, sucessMessage, LOGIN_BUTTON_ID);
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

    function isLoginValid() {
        let regExpression = /^[A-Za-z]+$/;
        let login = document.getElementById(LOGIN_FIELD_ID);
        if (login.value.match(regExpression) && login.value.length > 4) {
            return true;
        } else {
            return false;
        }
    }

    function isPasswordValid() {
        let regExpression = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#\$%\^&\*]).{8,}$/;
        let password = document.getElementById(PASSWORD_FIELD_ID);
        if (password.value.match(regExpression)) {
            return true;
        } else {
            return false;
        }
    }

    function updatePasswordValidityMessage() {
        let warningElemId = "passwordWarning";
        let warningMessage = "Co najmniej 8 znaków, mała i duża litera oraz znak specjalny.";

        if (isPasswordValid() === true) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, PASSWORD_FIELD_ID);
        }
    }

    function updateLoginAvailabilityMessage() {
        let validityWarningElemId = "validLoginWarning";
        let wrongLoginFormatWarningMessage = "Login musi składać się z 5 znaków i zawierać tylko litery."
        if (isLoginValid() === true) {
            removeWarningMessage(validityWarningElemId);
        } else {
            showWarningMessage(validityWarningElemId, wrongLoginFormatWarningMessage, LOGIN_FIELD_ID)
        }
    }

    function changeButtonStatus() {
        if (document.getElementById("button-log-form").disabled) {
            document.getElementById("button-log-form").disabled = false;
        } else {
            document.getElementById("button-log-form").disabled = true;
        }
    }

});