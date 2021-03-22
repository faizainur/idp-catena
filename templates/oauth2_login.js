window.addEventListener("load", function () {
        const form = document.getElementById("oauthLogin");
        var passwordInput = document.getElementById("passwordInput");
        var emailInput = document.getElementById("emailInput");
        var passwordHelper = document.getElementById("passwordFieldRequiredHelper")
        var emailHelper = document.getElementById("emailFieldRequiredHelper")

        var checkEmailPaswrodDiv = document.getElementById("checkEmailPassword")
        var checkEmailPasswordStatus = false

        if (checkEmailPasswordStatus) {
            checkEmailPaswrodDiv.classList.remove("is-hidden")
        }

        function sendData() {
          const XHR = new XMLHttpRequest();

         

          XHR.addEventListener("load", function (event) {
            alert(event.target.responseText);
            event.target.res
          });

          // Define what happens in case of error
          XHR.addEventListener("error", function (event) {
            alert("Oops! Something went wrong.");
          });

        //   XHR.open("POST", {{.url}});
          XHR.send(FD);

          //   console.log(FD);
        }

        form.addEventListener("submit", function (event) {
            event.preventDefault();

             const FD = new FormData(form);
            //  console.log(FD.get("email"))

            if (FD.get("email") === "") {
                emailInput.classList.add("is-danger")
                emailHelper.classList.remove("is-hidden")
            } else if (FD.get("password") === "") {
                passwordInput.classList.add("is-danger")
                passwordHelper.classList.remove("is-hidden")
            }

            // if (passwordField1 !== passwordField2) {
            //     alert("Password not the same")
            //     return
            // } else {
            //     sendData()
            // }
        });

        passwordInput.addEventListener('input', function(event) {
            if (event.target.value === "") {
                passwordInput.classList.add("is-danger")
                passwordHelper.classList.remove("is-hidden")
            } else {
                passwordInput.classList.remove("is-danger")
                passwordHelper.classList.add("is-hidden")
            }
        })

        emailInput.addEventListener('input', function(event) {
            if (event.target.value === "") {
                emailInput.classList.add("is-danger")
                emailHelper.classList.remove("is-hidden")
            } else {
                emailInput.classList.remove("is-danger")
                emailHelper.classList.add("is-hidden")
            }
        })
      });