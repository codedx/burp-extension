/*
 * Copyright (C) 2016 Code Dx, Inc. - http://www.codedx.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.secdec.codedx.security;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Formatter;
import java.util.StringTokenizer;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLException;
import javax.swing.JOptionPane;

import org.apache.http.conn.ssl.DefaultHostnameVerifier;

import burp.BurpExtender;

/**
 * An InvalidCertificateStrategy implementation that opens a dialog, prompting
 * the user for their choice of action.
 */
public class InvalidCertificateDialogStrategy implements InvalidCertificateStrategy {

	private final HostnameVerifier defaultHostVerifier;
	private final String host;
	private BurpExtender burpExtender;

	private final static String dialogTitle = "Untrusted Digital Certificate";
	private final static String[] dialogButtons = { "Reject", "Accept Temporarily", "Accept Permanently" };
	
	public InvalidCertificateDialogStrategy(HostnameVerifier defaultHostVerifier, String host, BurpExtender be) {
		this.defaultHostVerifier = defaultHostVerifier;
		this.host = host;
		this.burpExtender = be;
	}

	@Override
	public CertificateAcceptance checkAcceptance(Certificate genericCert, CertificateException certError) {
		if (genericCert instanceof X509Certificate && defaultHostVerifier instanceof DefaultHostnameVerifier) {
			X509Certificate cert = (X509Certificate) genericCert;
			DefaultHostnameVerifier verifier = (DefaultHostnameVerifier) defaultHostVerifier;

			StringBuilder dialogMessage = new StringBuilder(
					"Unable to establish a secure connection because the certificate is not trusted.\n\nIssuer: ");

			dialogMessage.append(cert.getIssuerDN().toString());

			try {
				dialogMessage.append("\n\nSHA-256  Fingerprint: ");
				dialogMessage.append(toHexString(getSHA256(cert.getEncoded()), ":"));
			} catch (CertificateEncodingException e) {
				e.printStackTrace();
				// this shouldn't actually ever happen
			}

			try {
				verifier.verify(host, cert);
			} catch (SSLException e) {
				String cn = getCN(cert);

				dialogMessage.append("\n\nHost Mismatch: ");
				String msg;
				if (cn != null) {
					msg = String.format("Expected '%s', but the certificate is for '%s'.", host, cn);
				} else {
					msg = e.getMessage();
				}
				dialogMessage.append(msg);
			}

			// Open the dialog, and return its result
			String choice = (String) JOptionPane.showInputDialog(burpExtender.getUiComponent(),
					dialogMessage.toString(), dialogTitle, JOptionPane.QUESTION_MESSAGE, null, dialogButtons, null);
			switch (choice) {
			case ("Reject"):
				return CertificateAcceptance.REJECT;
			case ("Accept Temporarily"):
				return CertificateAcceptance.ACCEPT_TEMPORARILY;
			case ("Accept Permanently"):
				return CertificateAcceptance.ACCEPT_PERMANENTLY;
			}
		}
		return CertificateAcceptance.REJECT;
	}

	public static byte[] getSHA256(byte[] input) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.reset();
			return md.digest(input);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}

	public static String toHexString(byte[] bytes, String sep) {
		Formatter f = new Formatter();
		for (int i = 0; i < bytes.length; i++) {
			f.format("%02x", bytes[i]);
			if (i < bytes.length - 1) {
				f.format(sep);
			}
		}
		String result = f.toString();
		f.close();
		return result;
	}

	private static String getCN(X509Certificate cert) {
		String principal = cert.getSubjectX500Principal().toString();
		StringTokenizer tokenizer = new StringTokenizer(principal, ",");
		while (tokenizer.hasMoreTokens()) {
			String token = tokenizer.nextToken();
			int i = token.indexOf("CN=");
			if (i >= 0) {
				return token.substring(i + 3);
			}
		}
		return null;
	}
}
