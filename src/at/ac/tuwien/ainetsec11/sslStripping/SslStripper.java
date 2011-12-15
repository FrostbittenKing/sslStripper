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
import java.net.URLConnection;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

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
	private String additionalParams;


	public HTTPRequest(String method, String resource, String host) {
		super();
		this.method = method;
		this.resource = resource;
		this.host = host;
	}



	public HTTPRequest(String method, String resource, String host, int port, String additionalParams) {
		super();
		this.method = method;
		this.resource = resource;
		this.host = host;
		this.port = port;
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
			int port;
			String[] methodLineArray = methodLine.split(" ");
			if (methodLineArray[0].matches("GET") || methodLineArray[0].matches("POST") || methodLineArray[0].matches("PUT") || methodLineArray[0].matches("DELETE")) {
				method = methodLineArray[0];
				resource = methodLineArray[1];
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

			return new HTTPRequest(method, resource, host, port, additionalParams);

		}
		catch (IOException e) {

		}
		return null;
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
		rewritten += request.getMethod() + " " + request.getResource() + " HTTP/1.0\r\n";
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
				//httpSocket = new Socket(host, port)

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
				httpConnectionInput.close();
				httpConnectionOutput.close();
				httpSocket.close();
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
