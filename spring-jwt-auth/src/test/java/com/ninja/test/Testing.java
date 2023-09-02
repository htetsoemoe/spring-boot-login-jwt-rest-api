package com.ninja.test;

import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;

@SpringBootConfiguration
@SpringBootTest
public class Testing {
	@Test
	@Disabled
	void test() {
		String status = HttpStatus.Series.SUCCESSFUL.toString().toLowerCase();
		System.out.println("status: %s".formatted(status));
	}
	
	@Test
	void test1() {
		String status = HttpStatus.Series.valueOf(HttpStatus.OK.value()).toString().toLowerCase();
		System.out.println("status: %s".formatted(status));
	}

}
