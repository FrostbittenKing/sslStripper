

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Iterator;
import java.util.Timer;
import java.util.TimerTask;
import java.util.Vector;

import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

public class SslStripper {

	public static final int PROXY_PORT = 40034;
	public static String TARGET_URL="http://inetsec.iseclab.org";
	/**
	 * @param args
	 */
	public static void main(String[] args) {
		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory)SSLServerSocketFactory.getDefault();

		SSLServerSocket serverSocket = null;
		try {
			serverSocket = (SSLServerSocket)sslServerSocketFactory.createServerSocket(PROXY_PORT);

		}
		catch (IOException e) {
			System.err.println(e.getMessage());
			return;
		}
		MyThreadExecutor executor = MyThreadExecutor.getInstance();
		executor.execute(new SslSocketDispatcher(serverSocket, PROXY_PORT));

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

class SslSocketDispatcher implements Runnable {
	private SSLServerSocket socket;
	private int port;
	public SslSocketDispatcher(SSLServerSocket serverSocket, int proxyPort) {
		socket = serverSocket;
		port = proxyPort;

	}
	public void run() {
		while(!socket.isClosed()) {
			try {
				String[] enabledSuites = socket.getEnabledCipherSuites();
				for (int i = 0; i < enabledSuites.length; i++) {
					System.out.println(enabledSuites[i]);
				}
				MyThreadExecutor.getInstance().execute(new StripperThread((SSLSocket)socket.accept(), port));
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

class StripperThread implements Runnable {

	private SSLSocket socket;
	private int port;
	private Vector filterChain;

	public StripperThread(SSLSocket socket, int port) {
		this.socket = socket;
		this.port = port;
		filterChain = new Vector();
		filterChain.add(new SslStripperFilter());
	}

	public void run() {
		try {
			BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			BufferedWriter output = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
			String inputLine = input.readLine();
			System.out.println(inputLine);
			String filteredData = inputLine;

			Iterator filterIterator = filterChain.iterator();
			while (filterIterator.hasNext()) {
				Filter currentFilter = (Filter)filterIterator.next();
				filteredData = currentFilter.transform(filteredData);
			}
			output.write(filteredData);
			output.close();
			input.close();
			socket.close();
		}
		catch (IOException e) {
			System.err.println("unexpected disconnect");
		}
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
