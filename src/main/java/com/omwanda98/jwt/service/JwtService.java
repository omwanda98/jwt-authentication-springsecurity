package com.omwanda98.jwt.service;

import java.util.Date;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.omwanda98.jwt.model.User;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	private final String SECRET_KEY="970d6a182b0ab6be162f99eabfd187d295ebd99e990e35758fb3d763363e902c";
	//extract username
	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}
	
	//validate token
	public boolean isValid(String token, UserDetails user) {
		String username = extractUsername(token);
		return username.equals(user.getUsername()) && !isTokenExpired(token);
	}
	
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}
	
	private Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	//extract a specific property from token payload
	public <T> T extractClaim(String token, Function<Claims, T> resolver) {
		Claims claims = extractAllClaims(token);
		return resolver.apply(claims);
	}
	//extract payload from token
	private Claims extractAllClaims(String token) {
		return Jwts
				.parser()
				.verifyWith(getSigninKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}
	
	public String generateToken(User user) {
		String token = Jwts
				.builder()
				.subject(user.getUsername())
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis() + 24*60*60*1000))
				.signWith(getSigninKey())
				.compact();
		return token;
	}
	
	//create signinkey
	private SecretKey getSigninKey(){
		byte[] keyBytes = Decoders.BASE64URL.decode(SECRET_KEY);
		return Keys.hmacShaKeyFor(keyBytes);
				
	}
	
}
