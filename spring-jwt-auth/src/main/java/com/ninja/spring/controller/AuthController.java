package com.ninja.spring.controller;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ninja.spring.models.ERole;
import com.ninja.spring.models.Role;
import com.ninja.spring.models.User;
import com.ninja.spring.payload.request.LoginRequest;
import com.ninja.spring.payload.request.SignupRequest;
import com.ninja.spring.payload.response.MessageResponse;
import com.ninja.spring.payload.response.UserInfoResponse;
import com.ninja.spring.repo.RoleRepository;
import com.ninja.spring.repo.UserRepository;
import com.ninja.spring.security.jwt.JwtUtils;
import com.ninja.spring.security.service.UserDetailsImpl;

import jakarta.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	JwtUtils jwtUtils;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@Autowired 
	UserRepository userRepository;
	
	@Autowired
	RoleRepository roleRepository;
	
	@PostMapping("/signin")
	public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
		
		// Create login UserName and Password with UsernamePasswordAuthenticationToken that validate with AuthenticationManager
		Authentication authentication = authenticationManager
				.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		
		// Set Fully Authenticated Object to SecurityContextHolder
		SecurityContextHolder.getContext().setAuthentication(authentication);
		
		// Get Principal(Current Logged In User) from authenticated object
		UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
		
		// Generate JWT Cookie using UserDetails
		ResponseCookie jwtCookie = jwtUtils.generateJwtCookie(userDetails);
		
		// Get Granted Authorities from UserDetails
		List<String> roles = userDetails.getAuthorities().stream()
				.map(item -> item.getAuthority())
				.collect(Collectors.toList());
		
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
				.body(new UserInfoResponse(userDetails.getId(), 
						userDetails.getUsername(), 
						userDetails.getEmail(), 
						roles));
	}
	
	@PostMapping("/signout")
	public ResponseEntity<?> logoutUser() {
		ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
		return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
				.body(new MessageResponse(HttpStatus.Series.valueOf(HttpStatus.OK.value()).toString().toLowerCase(), 
						"You've been sign out!"));
	}
	
	
	// New User SignUp EndPoint
	@PostMapping("/signup")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		// Checks user-name and email already exist in database
		if (userRepository.existsByUsername(signUpRequest.getUsername())) {
			return ResponseEntity.badRequest().body(new MessageResponse(
					HttpStatus.Series.valueOf(HttpStatus.BAD_REQUEST.value()).toString().toLowerCase(), 
					"Username is already exists!"));
		}
		
		if (userRepository.existsByEmail(signUpRequest.getEmail())) {
			return ResponseEntity.badRequest().body(new MessageResponse(
					HttpStatus.Series.valueOf(HttpStatus.BAD_REQUEST.value()).toString().toLowerCase(), 
					"Email is already exists!"));
		}
		
		// Create New User's Account
		User user = new User(signUpRequest.getUsername(), 
				signUpRequest.getEmail(), 
				passwordEncoder.encode(signUpRequest.getPassword()));
		
		// get user's role
		Set<String> usrRoles = signUpRequest.getRole();
		Set<Role> roles = new HashSet<>();
		
		if (usrRoles == null) {
			Role userRole = roleRepository.findByName(ERole.ROLE_USER)
					.orElseThrow(() -> new RuntimeException("Role is not found!"));
			roles.add(userRole);
		} else {
			usrRoles.forEach(role -> {
				switch (role) {
				case "admin": {
					Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
							.orElseThrow(() -> new RuntimeException("Role is not found!"));
					roles.add(adminRole);
					
					break;
				}
				case "mod": {
					Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
							.orElseThrow(() -> new RuntimeException("Role is not found!"));
					roles.add(modRole);
					
					break;
				}
				default:
					Role userRole = roleRepository.findByName(ERole.ROLE_USER)
							.orElseThrow(() -> new RuntimeException("Role is not found!"));
					roles.add(userRole);
				}
			});
		}
		
		// Set User's Roles
		user.setRoles(roles);		
		// Save to Database
		userRepository.save(user);
		
		return ResponseEntity.ok(new MessageResponse(
				HttpStatus.Series.valueOf(HttpStatus.CREATED.value()).toString().toLowerCase(), 
				"User Registered Successfully!"));
	}

}
