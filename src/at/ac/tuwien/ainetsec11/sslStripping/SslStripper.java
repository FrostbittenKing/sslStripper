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
import java.util.ArrayList;
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
	abstract String transform(String data);
}

class SslStripperFilter extends Filter {

	String transform(String data) {
		return data;
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
			parameters.put(kv[0], kv[1]);
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

class HTTPRequestParser {
	private static HTTPRequestParser _instance = new HTTPRequestParser();
	private String originalRequest;


	public static HTTPRequestParser getInstance() {
		return _instance;
	}

	private HTTPRequestParser() {

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
					params = new HTTPRequestParameters();
				//	params = new HTTPRequestParameters(resourceParamsArray[1]);
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
					additionalParams += readLine + "\r\n";
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
	
	public String read() throws IOException {
		int toRead;
		String returnData = "";
		
		while(input.read(readBuffer) != -1) {
			returnData += new String(readBuffer);
		}
		return returnData;
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

	private Vector filterChain;
	private Socket socket;
	private Socket httpSocket;
	public Proxy(Socket socket) {
		this.socket = socket;
		filterChain = new Vector();
		filterChain.add(new SslStripperFilter());
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

	public void proxyConnection() {

		/*Iterator filterIterator = filterChain.iterator();
		while (filterIterator.hasNext()) {
			Filter currentFilter = (Filter)filterIterator.next();
			filteredData = currentFilter.transform(filteredData);
		}*/
		BufferedReader input = null;
		BufferedOutputStream output = null;
		BufferedInputStream httpConnectionOutput = null;
		OutputStreamWriter httpConnectionInput = null;
		SocketConnection connection = null;
		try {
			input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			output = new BufferedOutputStream(socket.getOutputStream());
			String inputString = "";
			byte[] writeBuffer = new byte[65535];
			while(input.ready()) {
				inputString += input.readLine() + "\n";
			}

			//output.write(inputString);
			HTTPRequest request = HTTPRequestParser.getInstance().parse(inputString);

			if (request == null) {
				System.err.println("parsing error oh noes");
				output.close();
				input.close();
				socket.close();

			}
			/*
			connection = SocketConnectorFactory.createSocketConnection(request.getHost());
			
			String rewrittenRequest = rewriteRequest(request);
			connection.getInputStream();
			connection.getOutputStream();
			connection.write(rewrittenRequest);
			String retData = connection.read();
			System.err.println(retData);
			output.write(retData);
			output.flush();
			System.err.println("file done");
			connection.close();
			output.close();
			input.close();
			*/
		//	httpSocket = new Socket(host, port)

			
			httpSocket = new Socket(request.getHost(), 80);
			httpSocket.setReceiveBufferSize(65535);
			//httpSocket.setSoTimeout(10000);

			httpConnectionOutput = new BufferedInputStream(httpSocket.getInputStream());
			httpConnectionInput = new OutputStreamWriter(httpSocket.getOutputStream());

			String rewrittenRequest = rewriteRequest(request);
			httpConnectionInput.write(rewrittenRequest);
			httpConnectionInput.flush();
			int toRead;
			boolean read = false;
			int availableBytes = 0;

			while((toRead = httpConnectionOutput.read(writeBuffer)) != -1) {
				output.write(writeBuffer, 0, toRead);
				//	System.err.println(new String(writeBuffer));
				System.err.println(httpConnectionOutput.available());

			}
			System.err.println("done file");
			output.close();
			input.close();
			httpConnectionInput.close();
			httpConnectionOutput.close();
			httpSocket.close();
		

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
