document.addEventListener('DOMContentLoaded', function (event) {

    const POST = "POST";
    const URL = "https://localhost/";
    let token_url = document.getElementById("token_url").textContent;

    const PASSWORD_FIELD_ID = "password";
    const REPEAT_PASSWORD_FIELD_ID = "second_password";
    const SUBMIT_BUTTON_ID = "button-pass-rec";
    const ENTROPHY_BAR_ID = "passwordEntropy";
    const ENTROPHY_TEXT_ID = "passwordEntropyText";

    var HTTP_STATUS = {OK: 200, CREATED: 201, BAD_REQUEST: 400, NOT_FOUND: 404};

    prepareEventOnPasswordChange();
    prepareEventOnRepeatPasswordChange();

    let recoveryForm = document.getElementById("recovery-form");

    recoveryForm.addEventListener("submit", function (event) {
        event.preventDefault();

        if(isFormOK()) {
            submitRegisterForm();
            setTimeout(function(){
                if (document.getElementById("correctRegister") !== null) {
                    window.location = "/";
                }
            }, 4000);
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
        let passwordWarningElemId = document.getElementById("passwordWarning");
        let repeatPasswordWarningElemId = document.getElementById("repeatPasswordWarning");

        

        if( passwordWarningElemId === null &&
            repeatPasswordWarningElemId === null) {
            return true;
        } else {
            return false;
        }
    }

    function isAnyInputEmpty() {
        if (document.getElementById(PASSWORD_FIELD_ID).value === "" ||
            document.getElementById(REPEAT_PASSWORD_FIELD_ID).value === ""
        ) {
            return true;
        } else {
            return false;
        }
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

    function submitRegisterForm() {
        let registerUrl = URL + "reset_password/" + token_url;
        let csrfToken = document.getElementById("csrf_token");

        let registerParams = {
            method: POST,
            body: new FormData(recoveryForm),
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

    function getRegisterResponseData(response) {  // to remove
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
        let sucessMessage = "Hasło zostało zmienione poprawnie. Zaraz nastąpi przekierowanie.";
        let warningRegisterInfo = "unsuccessfulRegister";
        let warningMessage = "Podczas zmiany hasła wystąpił błąd. Wygeneruj nowy link.";

        if (status !== HTTP_STATUS.CREATED && status !== HTTP_STATUS.OK) {
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
        let warningMessage = "Co najmniej 8 znaków, mała i duża litera oraz znak specjalny.";

        if (isPasswordValid() === true) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, PASSWORD_FIELD_ID);
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