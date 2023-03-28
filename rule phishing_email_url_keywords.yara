rule phishing_email_url_keywords 
{
    meta:
        author = "Julio Papaqui"
        description = "Detects phishing URLs and keywords"

    strings:
        $phishing_keywords = "Urgent", "Important", "Verify", "Confirm", "Update", "Login", "Password", "Account", "Security Alert", "Suspicious Activity"
        $phishing_links = "http://", "https://", "www."
    condition:
        all of ($phishing_keywords[*], $phishing_links[*]) and (any of them)
}

//Esta regla busca palabras clave específicas que se usan comúnmente en correos electrónicos de phishing, 
//como "Urgente" o "Alerta de seguridad", así como enlaces comunes que se usan en correos electrónicos de phishing