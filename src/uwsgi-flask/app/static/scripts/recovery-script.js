document.addEventListener('DOMContentLoaded', function (event) {

    const POST = "POST";
    const URL = "https://localhost/";

    const LOGIN_FIELD_ID = "login";
    const BIRTH_DATE_FIELD_ID = "birthDate";
    const EMAIL_FIELD_ID = "email";
    const SUBMIT_BUTTON_ID = "button-pass-rec";


    var HTTP_STATUS = {OK: 200, CREATED: 201, BAD_REQUEST: 400, NOT_FOUND: 404};

    prepareEventOnLoginChange();
    prepareEventOnDateChange();
    prepareEventOnEmailChange();

    let passwordRecoveryForm = document.getElementById("pass-rec-form");

    passwordRecoveryForm.addEventListener("submit", function (event) {
        event.preventDefault();

        if(isFormOK()) {
            submitRegisterForm();
            
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
        let birthDateYearWarningElemId = document.getElementById("yearWarning");
        let emailWarningElemId = document.getElementById("emailWarning");

        

        if( birthDateYearWarningElemId === null &&
            emailWarningElemId === null ) {
            return true;
        } else {
            return false;
        }
    }

    function isAnyInputEmpty() {
        if (
            document.getElementById(BIRTH_DATE_FIELD_ID).value === "" ||
            document.getElementById(EMAIL_FIELD_ID).value === ""
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

    function prepareEventOnDateChange() {
        let dateInput = document.getElementById(BIRTH_DATE_FIELD_ID);
        dateInput.addEventListener("change", updateDateValidityMessage);
    }

    function prepareEventOnEmailChange() {
        let email = document.getElementById(EMAIL_FIELD_ID);
        email.addEventListener("change", updateEmailValidityMessage);
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
        let registerUrl = URL + "reset_password";
        let csrfToken = document.getElementById("csrf_token");

        let registerParams = {
            method: POST,
            body: new FormData(passwordRecoveryForm),
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
        let sucessMessage = "Jeżeli podałeś poprawne dane, email z linkem aktywacyjnym został wysłany na podany powyżej adres korespondencyjny. Link będzie ważny tylko 10 minut.";
        let warningRegisterInfo = "unsuccessfulRegister";
        let warningMessage = "Podczas odzyskiwania wystąpił błąd.";

        if (status !== HTTP_STATUS.OK) {
            removeWarningMessage(correctRegisterInfo);
            showWarningMessage(warningRegisterInfo, warningMessage, SUBMIT_BUTTON_ID);
            console.log("Errors: " + correctResponse.errors);
        } else {
            removeWarningMessage(warningRegisterInfo);
            showSuccesMessage(correctRegisterInfo, sucessMessage, SUBMIT_BUTTON_ID);
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


    function updateEmailValidityMessage() {
        let warningElemId = "emailWarning";
        let warningMessage = "Proszę podać poprawny adres email.";
        let email = document.getElementById(EMAIL_FIELD_ID).value;
        let regExpression = /^[a-z0-9A-Z]+[\._]?[a-z0-9A-Z]+[@]\w+[.]\w{2,3}$/;

        if (email.match(regExpression)) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, EMAIL_FIELD_ID);
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


  

});