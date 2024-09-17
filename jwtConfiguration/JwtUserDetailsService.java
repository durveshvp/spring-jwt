package com.techtrail.onco.configuration.jwtConfiguration;

import java.util.ArrayList;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.techtrail.onco.entity.User;
import com.techtrail.onco.registration.dao.IRegistrationDao;

@Service
@Transactional
public class JwtUserDetailsService implements UserDetailsService {


	@Autowired
	private IRegistrationDao registrationDaoService;

	@Override public UserDetails loadUserByUsername(String username) throws
	UsernameNotFoundException {
		User user = registrationDaoService.findUserByUsername(username);
		if (user == null) { throw new
			UsernameNotFoundException("User not found with username: " + username); }
		return new
				org.springframework.security.core.userdetails.User(user.getUsername(),
						user.getPassword(), new ArrayList<>()); 
	}


}