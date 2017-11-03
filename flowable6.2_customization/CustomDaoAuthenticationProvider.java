/* Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.flowable.app.security;

import java.util.ArrayList;

import org.apache.commons.lang3.StringUtils;
import org.json.JSONException;
import org.json.JSONObject;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.net.URL;
import java.net.URLEncoder;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.Environment;



/**
 * @author jbarrez
 */
public class CustomDaoAuthenticationProvider extends DaoAuthenticationProvider {
	private static final Logger LOGGER = LoggerFactory.getLogger(CustomDaoAuthenticationProvider.class);

    protected void additionalAuthenticationChecks(org.springframework.security.core.userdetails.UserDetails userDetails,
            org.springframework.security.authentication.UsernamePasswordAuthenticationToken authentication) throws org.springframework.security.core.AuthenticationException {

        // Overriding this method to catch empty/null passwords. This happens when users are synced with LDAP sync:
        // they will have an external id, but no password (password is checked against ldap).
        //
        // The default DaoAuthenticationProvider will choke on an empty password (an arrayIndexOutOfBoundsException
        // somewhere deep in the bowels of password encryption), hence this override
    	
    	if (StringUtils.isEmpty(userDetails.getPassword())) {
            throw new BadCredentialsException(messages.getMessage("AbstractUserDetailsAuthenticationProvider.badCredentials", "Bad credentials"));
        }
    	// super.additionalAuthenticationChecks(userDetails, authentication);
    	//Pru customized this method for Authenticated by calling AD authentication service
    	LOGGER.debug("[Pru]additionalAuthenticationChecks ...,");
    	String username = (authentication.getPrincipal() == null) ? "NONE_PROVIDED"
				: authentication.getName();
    	String presentedPassword = authentication.getCredentials().toString();
    	LOGGER.debug("CustomDaoAuthenticationProvider.additionalAuthenticationChecks ...{}",username);
    	// neu khac password admin thi raise error 
        String urlTemplate = environment.getProperty("api.authentication.urltemplate", String.class);
    	String url = String.format(urlTemplate,username,presentedPassword);
    	LOGGER.debug(urlTemplate);
    	LOGGER.debug(url);
		// optional default is GET
		try {
		
			 JSONObject postDataParams = new JSONObject();
	         postDataParams.put("userid", username);
	         postDataParams.put("password", presentedPassword);
	         String content ="" ;
	         if (url.startsWith("https://"))
	        	 content = sendPOSTHTTPSData(urlTemplate, postDataParams);
	         else 
	        	content = sendPOSTHTTPData(urlTemplate, postDataParams);
			 
			if (!content.toString().contains("OK")){
				LOGGER.debug("Authentication failed:{}",content.toString());
				
				throw new BadCredentialsException(messages.getMessage(
						"AbstractUserDetailsAuthenticationProvider.badCredentials",
						"Bad credentials"));
			}
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
			LOGGER.debug("Authentication failed:System Error:"+e.getMessage());
			
			throw new BadCredentialsException(messages.getMessage(
					e.getMessage(),
					"System Errror:"+e.getMessage()));
		}
    }
    
    @Autowired
    protected Environment environment;
    
    
    /*
    @Override
    public Authentication authenticate(Authentication authentication) 
      throws AuthenticationException {
  
        String name = authentication.getName();
        String password = authentication.getCredentials().toString();
        String username  =name ;
        UserDetails user =retrieveUser(username,
				(UsernamePasswordAuthenticationToken) authentication);
        Object principalToReturn = user;
        principalToReturn = user.getUsername();
		
        // use the credentials and authenticate against the third-party system
        
        LOGGER.info("CustomDaoAuthenticationProvider.authenticate {},{}",name,password);
        if(("user".equals(name) && "user".equals(password)) 
        		|| ("admin1".equals(name) && "admin".equals(password))){
        	LOGGER.info("Succesful authentication!");
        	//return new UsernamePasswordAuthenticationToken(name, password);	
        	return createSuccessAuthentication(principalToReturn, authentication, user);
        
        }
        
        LOGGER.info("Login fail!");
        
        return null;

        }
      */
    
    public  static String sendPOSTHTTPData(String urlpath, JSONObject json) throws BadCredentialsException {
        HttpURLConnection connection = null;
        HttpsURLConnection httpsconnection =null ;
        try {
            URL url=new URL(urlpath);
            connection = (HttpURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            OutputStreamWriter streamWriter = new OutputStreamWriter(connection.getOutputStream());
            streamWriter.write(json.toString());
            streamWriter.flush();
            StringBuilder stringBuilder = new StringBuilder();
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK){
                InputStreamReader streamReader = new InputStreamReader(connection.getInputStream());
                BufferedReader bufferedReader = new BufferedReader(streamReader);
                String response = null;
                while ((response = bufferedReader.readLine()) != null) {
                    stringBuilder.append(response + "\n");
                }
                bufferedReader.close();

               // LOGGER.debug("test", stringBuilder.toString());
                return stringBuilder.toString();
            } else {
            	//LOGGER.debug("test", connection.getResponseMessage());
            	throw new BadCredentialsException("Http does not response OK..");
            }
        } catch (Exception exception){
        	//LOGGER.debug("test", exception.toString());
        	throw new BadCredentialsException("System Error : "+ exception.getMessage());
            
        } finally {
            if (connection != null){
                connection.disconnect();
            }
        }
    }
    public  static String sendPOSTHTTPSData(String urlpath, JSONObject json) throws BadCredentialsException {
    	HttpsURLConnection connection = null;
        
        try {
            URL url=new URL(urlpath);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setDoInput(true);
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setRequestProperty("Accept", "application/json");
            OutputStreamWriter streamWriter = new OutputStreamWriter(connection.getOutputStream());
            streamWriter.write(json.toString());
            streamWriter.flush();
            StringBuilder stringBuilder = new StringBuilder();
            if (connection.getResponseCode() == HttpURLConnection.HTTP_OK){
                InputStreamReader streamReader = new InputStreamReader(connection.getInputStream());
                BufferedReader bufferedReader = new BufferedReader(streamReader);
                String response = null;
                while ((response = bufferedReader.readLine()) != null) {
                    stringBuilder.append(response + "\n");
                }
                bufferedReader.close();

               // LOGGER.debug("test", stringBuilder.toString());
                return stringBuilder.toString();
            } else {
            	//LOGGER.debug("test", connection.getResponseMessage());
            	throw new BadCredentialsException("Http does not response OK..");
            }
        } catch (Exception exception){
        	//LOGGER.debug("test", exception.toString());
        	throw new BadCredentialsException("System Error : "+ exception.getMessage());
            
        } finally {
            if (connection != null){
                connection.disconnect();
            }
        }
    }
    public static void main(String[] args) throws JSONException,BadCredentialsException {
    	String username ="admin1" ;
    	String presentedPassword ="Prudential02" ;
        System.out.println("Hello World!"); // Display the string.
        
        
    	//String urlTemplate= "http://localhost:5000/api/v1.0/ad/authen?userid=%s&password=%s";
    	
    	String urlTemplate= "http://localhost:5000/api/v1.0/ad/authen";
    	
    	String url = String.format(urlTemplate,username,presentedPassword);
        //String url = String.format("https://localhost:5000/api/v1.0/ad/authen?userid=%s&password=%s",username,presentedPassword);
    	
		LOGGER.debug(String.format("ULR:%s",url));
		
		 JSONObject postDataParams = new JSONObject();
         postDataParams.put("userid", username);
         postDataParams.put("password", presentedPassword);
         String output = sendPOSTHTTPData(urlTemplate,postDataParams);
         System.out.println(output);
         
    }
	}

		
  
