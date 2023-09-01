package com.ninja.spring.security.jwt;

import java.security.Key;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import org.springframework.web.util.WebUtils;

import com.ninja.spring.security.service.UserDetailsImpl;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

@Component
public class JwtUtils {
	private static final Logger logger = LoggerFactory.getLogger(JwtUtils.class);
	
	@Value("${ninja.app.jwtSecret}")
	private String jwtSecrete;
	
	@Value("${ninja.app.jwtExpirationMs}")
	private int jwtExpirationMs;
		
	@Value("${ninja.app.jwtCookieName}")
	private String jwtCookieName;
	
	public String getJwtFromCookies(HttpServletRequest request) {
		Cookie cookie = WebUtils.getCookie(request, jwtCookieName);
		if (cookie != null) {
			return cookie.getValue();		
		} else {
			return null;
		}
	}
	
	public ResponseCookie generateJwtCookie(UserDetailsImpl userPrinciple) {
		String jwt = generateTokenFromUsername(userPrinciple.getUsername());
		ResponseCookie cookie = ResponseCookie.from(jwtCookieName, jwt).path("/api").maxAge(24 * 60 * 60).httpOnly(true).build();
		return cookie;
	}
	
	public ResponseCookie getCleanJwtCookie() {
		ResponseCookie cookie = ResponseCookie.from(jwtCookieName, null).path("/api").build();
		return cookie;
	}
	
	public String getUserNameFromJwtToken(String token) {
		return Jwts.parserBuilder().setSigningKey(key()).build()
				.parseClaimsJws(token).getBody().getSubject();
	}
	
	public boolean validateJwtToken(String authToken) {
		try {
			Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
			return true;
		} catch (MalformedJwtException e) {
			logger.error("Invalid JWT token : {}".formatted(e.getMessage()));
		} catch (ExpiredJwtException e) {
			logger.error("JWT token is expired : {}".formatted(e.getMessage()));
		} catch (UnsupportedJwtException e) {
			logger.error("JWT token is unsupported : {}".formatted(e.getMessage()));
		} catch (IllegalArgumentException e) {
			logger.error("JWT claims strings is empty : {}".formatted(e.getMessage()));
		}
		
		return false;
	}
	
	// Helper method for generateTokenFromUsername
	private Key key() {
		return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecrete));
	}
	
	// Helper method for generateJwtCookie
	public String generateTokenFromUsername(String username) {
		return Jwts.builder()
				.setSubject(username)
				.setIssuedAt(new Date())
				.setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
				.signWith(key(), SignatureAlgorithm.HS256)
				.compact();			
	}
}
