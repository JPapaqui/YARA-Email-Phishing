rule phishing_emails_strings 
{
    meta:
        description = "Detects common characteristics of phishing emails"
        author = "Julio Papaqui"
    strings:
        $phishing_strings = {
            "Dear customer",
            "Click here",
            "Verify your account",
            "Urgent action required",
            "Your account will be suspended",
            "Security alert",
            "Login to your account",
            "Confirm your personal information",
            "Change your password",
            "Unusual activity detected",
            "Your account has been compromised"
        }
    condition:
        any of them
}

//Esta regla busca una lista de cadenas que se encuentran comúnmente en los correos electrónicos de phishing, 
//como "Haga clic aquí" o "Verifique su cuenta". Si alguna de estas cadenas se encuentra en un correo electrónico, 
//la regla se activará y alertará al usuario de que el correo electrónico puede ser un intento de phishing.