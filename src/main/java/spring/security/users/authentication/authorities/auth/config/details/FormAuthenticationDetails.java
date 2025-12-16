package spring.security.users.authentication.authorities.auth.config.details;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

public class FormAuthenticationDetails extends WebAuthenticationDetails {

    private final String secretKey;

    public FormAuthenticationDetails(HttpServletRequest request) {
        super(request);
        this.secretKey = request.getParameter("secretKey");
    }

    public String getSecretKey() {
        return this.secretKey;
    }
}
