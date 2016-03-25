package nl.trifork;

import nl.trifork.security.SpringSessionBackedSessionRegistry;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.session.ExpiringSession;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpSession;
import java.security.Principal;
import java.util.Collection;

import static org.springframework.session.FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME;

@SpringBootApplication
public class App extends WebSecurityConfigurerAdapter {

    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }

    @Autowired SpringSessionBackedSessionRegistry sessionRegistry;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //@formatter:off
        http.formLogin().and()
            .logout().and()
            .csrf().disable()
            .sessionManagement()
                .maximumSessions(2)
                    .sessionRegistry(sessionRegistry)
                    // set to true to prevent logins after reaching max sessions:
                    .maxSessionsPreventsLogin(false)
                    .and()
                .and()
            .authorizeRequests()
                .antMatchers("/").authenticated();
        //@formatter:on
    }

    @Controller
    static class TestController {

        @Autowired
        FindByIndexNameSessionRepository<? extends ExpiringSession> sessions;

        @RequestMapping("/")
        String listSessions(Principal principal, HttpSession session, Model model) {
            Collection<? extends ExpiringSession> userSessions = sessions.findByIndexNameAndIndexValue(PRINCIPAL_NAME_INDEX_NAME, principal.getName()).values();
            model.addAttribute("sessions", userSessions);
            model.addAttribute("currSessionId", session.getId());
            return "index";
        }
    }
}


