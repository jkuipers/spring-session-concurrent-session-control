package nl.trifork.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.session.ExpiringSession;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Component;

import java.security.Principal;
import java.util.List;

import static java.util.stream.Collectors.toList;
import static org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;

/**
 * SessionRegistry that retrieves session information from Spring Session, rather than maintaining it by itself.
 * This allows concurrent session management with Spring Security in a clustered environment.
 * <p>
 * Note that expiring a SessionInformation when reaching the configured maximum will simply delete an existing session
 * rather than marking it as expired, since Spring Session has no way to programmatically mark a session as expired.
 * This means that you cannot configure an expired URL; users will simply lose their session as if they logged out.
 * <p>
 * Relies on being able to derive the same String-based representation of the principal given to
 * {@link #getAllSessions(Object, boolean)} as used by Spring Session in order to look up the user's sessions.
 * <p>
 * Does not support {@link #getAllPrincipals()}, since that information is not available.
 */
@Component
public class SpringSessionBackedSessionRegistry implements SessionRegistry {

    private FindByIndexNameSessionRepository<ExpiringSession> sessionRepository;

    @SuppressWarnings("SpringJavaAutowiringInspection")
    @Autowired
    public SpringSessionBackedSessionRegistry(FindByIndexNameSessionRepository<ExpiringSession> sessionRepository) {
        this.sessionRepository = sessionRepository;
    }

    @Override
    public List<Object> getAllPrincipals() {
        throw new UnsupportedOperationException("SpringSessionBackedSessionRegistry does not support retrieving all principals, since Spring Session provides no way to obtain that information");
    }

    @Override
    public List<SessionInformation> getAllSessions(Object principal, boolean includeExpiredSessions) {
        return sessionRepository
                .findByIndexNameAndIndexValue(PRINCIPAL_NAME_INDEX_NAME, name(principal))
                .values()
                .stream()
                .filter(session -> includeExpiredSessions || !session.isExpired())
                .map(session -> new SpringSessionBackedSessionInformation(session, sessionRepository))
                .collect(toList());
    }

    @Override
    public SessionInformation getSessionInformation(String sessionId) {
        ExpiringSession session = sessionRepository.getSession(sessionId);
        if (session != null) {
            return new SpringSessionBackedSessionInformation(session, sessionRepository);
        }
        return null;
    }

    @Override
    public void refreshLastRequest(String sessionId) {
        ExpiringSession session = sessionRepository.getSession(sessionId);
        if (session != null) {
            session.setLastAccessedTime(System.currentTimeMillis());
            sessionRepository.save(session);
        }
    }

    /**
     * This is a no-op, as we don't administer sessions ourselves.
     */
    @Override
    public void registerNewSession(String sessionId, Object principal) {
    }

    /**
     * This is a no-op, as we don't administer sessions ourselves.
     */
    @Override
    public void removeSessionInformation(String sessionId) {
    }

    /**
     * Derives a String name for the given principal.
     */
    private String name(Object principal) {
        if (principal instanceof UserDetails) {
            return ((UserDetails) principal).getUsername();
        }
        if (principal instanceof Principal) {
            return ((Principal) principal).getName();
        }
        return principal.toString();
    }
}
