document.addEventListener('DOMContentLoaded', function (event) {

    const POST = "POST";
    const URL = "https://localhost/";

    const TITLE_FIELD_ID = "title";
    const NOTE_TEXT_FIEL_ID = "note_text"
    const PASSWORD_FIELD_ID = "password";
    const ADD_BUTTON_ID = "button-add-form";
    const SECURE_CHECHBOX_ID = "secure_checkbox"
    const PUBLIC_CHECKBOX_ID = "checkbox_public";
    var HTTP_STATUS = {OK: 200, CREATED: 201, BAD_REQUEST: 400, FORBIDDEN: 403, NOT_FOUND: 404};

    prepareEventOnTitleChange();
    prepareEventOnTextChange();
    prepareEventOnPasswordChange();

    let addForm = document.getElementById("add-form");

    addForm.addEventListener("submit", function (event) {
        event.preventDefault();
        changeButtonStatus();
        ifFormOkTryAddNote();
        changeButtonStatus();
    });


    function prepareEventOnTitleChange() {
        let titleInput = document.getElementById(TITLE_FIELD_ID);
        titleInput.addEventListener("change", updateTitleMessage);
    }
    
    function prepareEventOnPasswordChange() {
        let passwordInput = document.getElementById(PASSWORD_FIELD_ID);
        passwordInput.addEventListener("change", updatePasswordValidityMessage);
    }

    function prepareEventOnTextChange() {
        let textInput = document.getElementById(NOTE_TEXT_FIEL_ID);
        textInput.addEventListener("change", updateTextMessage);
    }

    const tryAddNote = async () => {
        let addUrl = URL + "add_new_note";
        let csrfToken = document.getElementById("csrf_token");

        let postParams = {
            method: POST,
            body: new FormData(addForm),
            redirect: "follow",
            "X-CSRF-Token": csrfToken
        };

        let res = await fetch (addUrl, postParams);
        displayInConsoleCorrectResponse(res);
        return await res;

    }


    const ifFormOkTryAddNote = async() => {
        
        let warningAddingInfoElemId = "unsuccessfulAdding";
        let warningMessage = "Notatka musi zawierać wszystkie pola wypełnione poprawnie.";
        if(isAnyEmptyImput()) {
            showWarningMessage(warningAddingInfoElemId, warningMessage, ADD_BUTTON_ID);
            return false;
        }

        removeWarningMessage(warningAddingInfoElemId);
        let validityWarningElemId = document.getElementById("unsuccessfulAdding");
        let passwordWarningElemId = document.getElementById("passwordWarning");
        let textWarningElemId = document.getElementById("textWarning");
        
        if( validityWarningElemId === null &&
            passwordWarningElemId === null &&
            textWarningElemId === null) {
                try{
                    let res = await tryAddNote();
                    setTimeout(function(){
                        if (document.getElementById("correctAdding") !== null) {
                             window.location = "notes";
                        }
                    }, 1000);
                } catch (err) {
                    console.log("Error catched; " + err); 
                }
        } else {
            return false;
        }
    }

    function isAnyEmptyImput() {
        let isPasswordNote = document.getElementById(SECURE_CHECHBOX_ID).checked;
        if(isPasswordNote) {
            if(document.getElementById(PASSWORD_FIELD_ID).value === "") {
                return true;
            }
        }
        
        if(
            document.getElementById(TITLE_FIELD_ID ).value === "" ||
            document.getElementById(NOTE_TEXT_FIEL_ID).value === "" 
        ) {
            return true;
        } else {
            return false;
        }
    }

    function displayInConsoleCorrectResponse(correctResponse) {
        let status = correctResponse.status;
        console.log("status " + status)
        let correctAddingInfo = "correctAdding";
        let sucessMessage = "Notatka została dodana pomyślnie. Za chwilę nastąpi przekierowanie.";
        let warningAddingInfo = "unsuccessfulAdding";
        let warningMessage = "Niepoprawne dane. Nie można dodać notatki.";

        if (status !== HTTP_STATUS.CREATED) {
            removeWarningMessage(correctAddingInfo);
            showWarningMessage(warningAddingInfo, warningMessage, ADD_BUTTON_ID);
        } else {
            removeWarningMessage(warningAddingInfo);
            showSuccesMessage(correctAddingInfo, sucessMessage, ADD_BUTTON_ID);
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

    function isTitleValid() {
        let regExpression = /^[A-Za-z0-9]+$/;
        let title = document.getElementById(TITLE_FIELD_ID);
        if (title.value.match(regExpression) && title.value.length > 2 && isSafeContent(title.value)) {
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

    function updateTextMessage() {
        let warningElemId = "textWarning";
        let warningMessage = "Tekst nie może zawierać niebezpiecznych znaków";
        text = document.getElementById(NOTE_TEXT_FIEL_ID);

        if (isSafeContent(text.value) === true) {
            removeWarningMessage(warningElemId);
        } else {
            showWarningMessage(warningElemId, warningMessage, NOTE_TEXT_FIEL_ID);
        }
    }

    function updateTitleMessage() {
        let validityWarningElemId = "validTitleWarning";
        let wrongTitleFormatWarningMessage = "Tytuł notatki musi składać się z co najmniej 3 znaków i zawierać tylko litery lub cyfry."
        if (isTitleValid() === true) {
            removeWarningMessage(validityWarningElemId);
        } else {
            showWarningMessage(validityWarningElemId, wrongTitleFormatWarningMessage, TITLE_FIELD_ID)
        }
    }

    function changeButtonStatus() {
        if (document.getElementById("button-add-form").disabled) {
            document.getElementById("button-add-form").disabled = false;
        } else {
            document.getElementById("button-add-form").disabled = true;
        }
    }
    
    function isSafeContent(text) {
        if((text).includes("'"))
            return false;
        if((text).includes("--"))
            return false;
        if((text).includes("/*"))
            return false;
        if((text).includes("#"))
            return false;
        if((text).includes(";"))
            return false;
        if((text).includes("<"))
            return false;
        if((text).includes(">"))
            return false;
        return true;
    }

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