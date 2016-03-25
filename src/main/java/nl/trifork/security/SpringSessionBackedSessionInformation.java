package nl.trifork.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.session.ExpiringSession;
import org.springframework.session.Session;
import org.springframework.session.SessionRepository;

import java.util.Date;

import static org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;

/**
 * Ensures that calling {@link #expireNow()} propagates to Spring Session,
 * since this session information contains only derived data and is not the authoritative source.
 */
public class SpringSessionBackedSessionInformation extends SessionInformation {

    /**
     * Tries to determine the principal's name from the given Session.
     *
     * @param session
     * @return the principal's name, or empty String if it couldn't be determined
     */
    private static String resolvePrincipal(Session session) {
        String principalName = session.getAttribute(PRINCIPAL_NAME_INDEX_NAME);
        if (principalName != null) {
            return principalName;
        }
        SecurityContext securityContext = session.getAttribute("SPRING_SECURITY_CONTEXT");
        if (securityContext != null && securityContext.getAuthentication() != null) {
            return securityContext.getAuthentication().getName();
        }
        return "";
    }

    private SessionRepository<? extends ExpiringSession> sessionRepository;
    private Logger logger = LoggerFactory.getLogger(getClass());

    public SpringSessionBackedSessionInformation(ExpiringSession session, SessionRepository<? extends ExpiringSession> sessionRepository) {
        super(resolvePrincipal(session), session.getId(), new Date(session.getLastAccessedTime()));
        this.sessionRepository = sessionRepository;
        if (session.isExpired()) {
            super.expireNow();
        }
    }

    @Override
    public void expireNow() {
        logger.debug("Deleting session {} for user '{}', presumably because max concurrent sessions was reached",
                getSessionId(), getPrincipal());
        super.expireNow();
        sessionRepository.delete(getSessionId());
    }

}
