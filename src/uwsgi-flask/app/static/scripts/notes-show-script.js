document.addEventListener('DOMContentLoaded', function (event) {

    const POST = "POST";
    const URL = "https://localhost/";

    const ID_NOTE_DECODE_ID = "id_decode";
    const PASSWORD_DECODE_ID = "password_decode";
    const BUTTON_DECODE_ID = "button_decode_form";
    
    const TEXT_DECODED_TABLE = "decoded_text";

    var HTTP_STATUS = { OK: 200, CREATED: 201, BAD_REQUEST: 400, UNAUTHORIZED: 401, FORBIDDEN: 403, NOT_FOUND: 404 };

    prepareEventOnIdChange();
    prepareEventOnPasswordChange();

    let decodeForm = document.getElementById("decode-form");

    decodeForm.addEventListener("submit", function (event) {
        event.preventDefault();
        changeButtonStatus();
        ifFormOkTryDecodeNote();
        changeButtonStatus();
    });


    function prepareEventOnIdChange() {
        let IdInput = document.getElementById(ID_NOTE_DECODE_ID);
        IdInput.addEventListener("change", updateIdMessage);
    }

    function prepareEventOnPasswordChange() {
        let passwordInput = document.getElementById(PASSWORD_DECODE_ID);
        passwordInput.addEventListener("change", updatePasswordValidityMessage);
    }

    const tryDecodeNote = async () => {
        let decodeUrl = URL + "decode_note";
        let csrfToken = document.getElementById("csrf_token");

        let postParams = {
            method: POST,
            body: new FormData(decodeForm),
            redirect: "follow",
            "X-CSRF-Token": csrfToken
        };
        let res = await fetch(decodeUrl, postParams);
        displayInConsoleCorrectResponse(res);
        return await res.json();
    }

    const ifFormOkTryDecodeNote = async () => {

        let warningDecodingInfoElemId = "unsuccessfulDecoding";
        let warningMessage = "Wszystkie pola są wymagane";
        if (isAnyEmptyImput()) {
            showWarningMessage(warningDecodingInfoElemId, warningMessage, BUTTON_DECODE_ID);
            return false;
        }

        removeWarningMessage(warningDecodingInfoElemId);
        let validityWarningElemId = document.getElementById("unsuccessfulDecoding");
        let passwordWarningElemId = document.getElementById("passwordWarning");
        let idWarningElemId = document.getElementById("idWarning");

        if (validityWarningElemId === null &&
            passwordWarningElemId === null &&
            idWarningElemId === null) {
            try {
                let res = await tryDecodeNote();
                if (document.getElementById("correctDecoding") !== null) {
                    displayDecodedNote(res);
                }
            } catch (err) {
                console.log("Error catched; " + err.message);
            }
        } else {
            return false;
        }
    }

    function isAnyEmptyImput() {
        if (
            document.getElementById(ID_NOTE_DECODE_ID).value === "" ||
            document.getElementById(PASSWORD_DECODE_ID).value === ""
        ) {
            return true;
        } else {
            return false;
        }
    }

    function displayInConsoleCorrectResponse(correctResponse) {
        let status = correctResponse.status;
        console.log("status " + status)
        let correctDecodingInfo = "correctDecoding";
        let sucessMessage = "Notatka została odkodowana pomyślnie";
        let warningDecodingInfo = "unsuccessfulDecoding";
        let warningMessage = "Niepoprawne id notatki lub hasło";

        if (status !== HTTP_STATUS.OK) {
            removeWarningMessage(correctDecodingInfo);
            showWarningMessage(warningDecodingInfo, warningMessage, BUTTON_DECODE_ID);
        } else {
            removeWarningMessage(warningDecodingInfo);
            showSuccesMessage(correctDecodingInfo, sucessMessage, BUTTON_DECODE_ID);
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

    function isIdValid() {
        let regExpression = /^[0-9]+$/;
        let id_note = document.getElementById(ID_NOTE_DECODE_ID);
        if (id_note.value.match(regExpression)) {
            return true;
        } else {
            return false;
        }
    }

    function isPasswordValid() {
        let regExpression = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#\$%\^&\*]).{8,}$/;
        let password = document.getElementById(PASSWORD_DECODE_ID);
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
            showWarningMessage(warningElemId, warningMessage, PASSWORD_DECODE_ID);
        }
    }

    function updateIdMessage() {
        let validityWarningElemId = "validIdWarning";
        let wrongFormatWarningMessage = "Id notatki to numer widoczny po jej boku w tabeli"
        if (isIdValid() === true) {
            removeWarningMessage(validityWarningElemId);
        } else {
            showWarningMessage(validityWarningElemId, wrongFormatWarningMessage, ID_NOTE_DECODE_ID)
        }
    }

    function changeButtonStatus() {
        if (document.getElementById(BUTTON_DECODE_ID).disabled) {
            document.getElementById(BUTTON_DECODE_ID).disabled = false;
        } else {
            document.getElementById(BUTTON_DECODE_ID).disabled = true;
        }
    }

    function displayDecodedNote(res) {
        decodedText = document.getElementById(TEXT_DECODED_TABLE);

        decodedText.innerHTML = res.text;
    }

});

