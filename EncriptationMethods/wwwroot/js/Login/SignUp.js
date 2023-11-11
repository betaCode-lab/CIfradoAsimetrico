"use strict"

const form = document.querySelector("#formSignUp");

window.onload = () => {
    loadEventsListeners();
}

function loadEventsListeners() {
    form.addEventListener("submit", createUser);
}

function createUser(e) {
    e.preventDefault();

    const isValid = validateForm();

    if (isValid) {
        form.submit();
    }
}

function validateForm() {

    const username = $("#username").val();
    const email = $("#email").val();
    const telephone = $("#telephone").val();
    const password = $("#password").val();

    if (username.trim() === "" || email.trim() === "" || telephone.trim() === "" || password.trim() === "") {
        createAlert("All fields are required");
        return false;
    }

    return true;
}

function createAlert(message) {

    const html = `
        <div class="form-group">
            <div class="alert alert-danger" role="alert">
                ${message}
            </div>
        </div>
    `;

    form.insertBefore(html, document.querySelector("#username"));
}