package com.zanol.scheduling;

import com.zanol.scheduling.security.filters.ApiKeyFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@SpringBootApplication
public class SchedulingApplication {

	public static void main(String[] args) {
		SpringApplication.run(SchedulingApplication.class, args);
	}

}

@Configuration
@EnableWebSecurity
class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${auth-token-header-name}")
	private String principalRequestHeader;

	@Value("${auth-token}")
	private String principalRequestValue;

	@Override
	protected void configure(HttpSecurity httpSecurity) throws Exception {
		ApiKeyFilter filter = new ApiKeyFilter(principalRequestHeader);

		filter.setAuthenticationManager(authentication -> {
			String principal = (String) authentication.getPrincipal();

			if (!principalRequestValue.equals(principal)) {
				throw new BadCredentialsException("The API key was not found or not the expected value.");
			}

			authentication.setAuthenticated(true);

			return authentication;
		});

		/*httpSecurity.csrf().disable()
				.authorizeRequests().antMatchers("/api/auth/generateToken").permitAll().
				anyRequest().authenticated().and().
				exceptionHandling().and().sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
		httpSecurity.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);*/

		httpSecurity.
				antMatcher("/api/**").
				csrf().disable().
				sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).
				and().addFilter(filter).authorizeRequests().anyRequest().authenticated();
	}
}