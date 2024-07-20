package io.security.springsecuritymaster;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class SessionInfoService {

    private final SessionRegistry sessionRegistry;

    public void sessionInfo() {
        List<Object> principals = sessionRegistry.getAllPrincipals();
        for (Object principal : principals) {
            List<SessionInformation> allSessions = sessionRegistry.getAllSessions(principal, false);

            for (SessionInformation allSession : allSessions) {
                System.out.println("allSession.getPrincipal() = " + allSession.getPrincipal());
                System.out.println("allSession.getSessionId() = " + allSession.getSessionId());
                System.out.println("allSession.getLastRequest() = " + allSession.getLastRequest());
            }
        }
    }
}
