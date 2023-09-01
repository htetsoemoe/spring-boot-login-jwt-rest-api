package com.ninja.spring.security.jwt;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ninja.spring.security.service.UserDetailsServiceImpl;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class AuthTokenFilter extends OncePerRequestFilter{
	
	@Autowired
	private JwtUtils jwtUtils;
	
	@Autowired
	private UserDetailsServiceImpl userDetialsService;
	
	private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		
		try {
			
			String jwt = parseJwt(request);
			if (null != jwt && jwtUtils.validateJwtToken(jwt)) {
				String userName = jwtUtils.getUserNameFromJwtToken(jwt);
				
				// After get username from jwt token, using username with UserDetailsService
				UserDetails userDetails = userDetialsService.loadUserByUsername(userName);
				
				// Create UsernamePasswordAutheticationToken validating by AuthenticatioManager or AuthenticationManager
				UsernamePasswordAuthenticationToken authenticationToken = 
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				
				authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				
				// Set Authenticated token to SecurityContextHolder
				SecurityContextHolder.getContext().setAuthentication(authenticationToken);
			}
			
		} catch (Exception e) {
			logger.error("Cannot set user authentication : {} ".formatted(e.getMessage()));
		}
		
		filterChain.doFilter(request, response);
		
	}
	
	// Helper method for parse JWT from HttpServletRequest
	private String parseJwt(HttpServletRequest request) {
		String jwt = jwtUtils.getJwtFromCookies(request);
		return jwt;
	}

}
