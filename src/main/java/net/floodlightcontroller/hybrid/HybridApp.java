package net.floodlightcontroller.hybrid;

import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.apache.derby.tools.sysinfo;
import org.json.JSONException;
import org.json.JSONObject;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.IFloodlightProviderService;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.DecimalFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.Set;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.http.websocketx.TextWebSocketFrame;



public class HybridApp implements IOFMessageListener, IFloodlightModule {

	
protected String url="http://192.168.1.74:8080/wm/acl/rules/json";//ip-controller+acl
protected String victim ="188.166.238.14";
protected IFloodlightProviderService floodlightProvider;
protected Set<Long> macAddresses;
protected static Logger logger;
protected int sampling_time = 10;
protected int timmer =1;
protected int rtt =1;
protected HashMap<String, String> ip = new HashMap<String,String>();
protected HashMap<String, Integer> req = new HashMap<String,Integer>();
String[] columnNames = {"No",
		"IP Address",
        "MAC Address",
        "Request times",
        "TurstV",
        "Entropy",
        "flag"};
protected String log = "1.no	2.time	3.gamma		4.totalpck		5.entropy		6.deviation		7.confidence \n";
protected String log_atttker= "";

protected  Object[][] data = new Object[100][7];
int[] reqPPS = new int[100];
int[] reqOld = new int[100];
int[] reqNew = new int[100];
int nub=0;
protected int i = 0;
protected int totalpck = 0;
protected static int flag = 0;
protected double usage = 0.0;
protected double gamma = 0.0;
protected double log_system_entropy = 0.0;
protected double log_system_deviation = 0.0;
protected double log_system_confidence = 0.0;
//HybridGUI call = new HybridGUI();

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		 return HybridApp.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
	    Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
	    return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
	    floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
	    macAddresses = new ConcurrentSkipListSet<Long>();
	    logger = LoggerFactory.getLogger(HybridApp.class);
//	    call.creategui(data);
//	    call.setgui();
	    for(int j=0;j<100;j++){
			reqOld[j] = 0;
		}
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		 floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		 Runnable caltrust = new Runnable() {
			    public void run() {
			    
				    //System.out.println(ip);
//				    for(int j=0 ;j<i ;j++){
//				    	System.out.println("MAC: "+data[j][2].toString()+ "Req:"+data[j][3].toString());
//				    }
				    trainGamma();
				    updateTrust();
				    Calendar cal = Calendar.getInstance();
			        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
//			        System.out.println( sdf.format(cal.getTime()) );
				   // call.updatateTable(data);
				    log = log + (timmer)+"\t"+sdf.format(cal.getTime()) + "\t"+ gamma +"\t"+totalpck+"\t"+log_system_entropy+
				    		"\t"+log_system_deviation+"\t"+log_system_confidence + "\n";
				   
				    greblog();
				    timmer++;
				  
				    //turn on flag
				    if(timmer==13){
				    	flag=1;
				    }

				    if(timmer==25){
				    	int temp = 0;
				    	for(int j=0;j<i;j++){
				    		System.out.println(data[j][1].toString() + " " +data[j][6].toString());
				    	}
				    	for(int j=0;j<i;j++){
				    		if(Integer.parseInt(data[j][6].toString()) == -1){
				    			temp++;
				    		}
				    	}
			 //   	log = log + log_atttker;
				    	log = log + temp+"/15 accuracy = "+(temp/15.0)*100;
				    	greblog();
				    	
					    	System.exit(0);
					    }
				  
   
			    }
		 	
			};
			ScheduledExecutorService executor = Executors.newScheduledThreadPool(1);
			executor.scheduleAtFixedRate(caltrust, 0, sampling_time, TimeUnit.SECONDS);

	}
	public void channelRead0(ChannelHandlerContext ctx, TextWebSocketFrame msg) throws Exception {
	     msg.retain(); // ferrybig: fixed bug http://stackoverflow.com/q/34634750/1542723
	     ctx.fireChannelRead(msg);
	     //group.writeAndFlush(msg.retain());
	}

	@Override
	   public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
	   
	        Ethernet eth = IFloodlightProviderService.bcStore.get(cntx,IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
			int countReq = 0;
			 Long sourceMACHash = eth.getSourceMACAddress().getLong();
		     String srcmacAddress = eth.getSourceMACAddress().toString();
		        
		     
		       if (!macAddresses.contains(sourceMACHash)) {
		            macAddresses.add(sourceMACHash);
		            logger.info("MAC Address: {} seen on switch: {}",
		                    eth.getSourceMACAddress().toString(),
		                    sw.getId().toString());
    
		        }
		        IPv4 ipv4 = (IPv4) eth.getPayload();
	            /* Various getters and setters are exposed in IPv4 */	       
	            IPv4Address scrIp = ipv4.getSourceAddress();
	            TCP tcp = (TCP) ipv4.getPayload();
	            TransportPort dstPort = tcp.getDestinationPort();
	            if(!ip.containsKey(srcmacAddress) && scrIp.toString().contains("10.0.0") && dstPort.toString().equals("80")){
	            	ip.put(srcmacAddress, scrIp.toString());
	            	req.put(srcmacAddress, countReq);
	            	addData(i,scrIp.toString(),srcmacAddress.toString(),countReq,0.0,0.0,0);
	            }
	            else{
	            	if(dstPort.toString().equals("80")){
	            	countReq = req.get(srcmacAddress);
	            	countReq++;
	            	req.put(srcmacAddress, countReq);
	            	updateReq(srcmacAddress,countReq);
	            	}
	
	            }
	 

	        return Command.CONTINUE;
	    }
	

	protected void addData(int number, String ip, String mac, int req, double trust, double entropy, int flag) {
		
		data[i][0]= i+1;
		data[i][1]= ip;
		data[i][2]= mac;
		data[i][3]= req;
		data[i][4]= 0.0;
		data[i][5]= 0.0;
		data[i][6]= 0;
		i++;
		
	}
	
	protected void updateReq(String mac,int reqNew){
		System.out.println(mac+" "+reqNew);
		for(int j = 0 ;j<i;j++){
			if(data[j][2].equals(mac)){
				data[j][3]=reqNew;		
			}
		}
		
		
	}
	protected void trainGamma() {
		// TODO Auto-generated method stub
		usage = 0.0;
		for(int j=0 ; j<i ;j++){
			reqNew[j] = Integer.parseInt(data[j][3].toString());
			reqPPS[j] =reqNew[j]-reqOld[j]; 
			totalpck+= reqPPS[j];
		}
		
		for(int j = 0 ;j<i;j++){	
			
			System.out.println("new old["+ j + "]" + " = " +reqOld[j]);
			System.out.println("new req["+ j + "]" + " = " +reqNew[j]);
			usage += reqPPS[j];
			reqOld[j]=reqNew[j];
		}
			
			gamma = usage/(i*10.0);
			System.out.println("Gamma =  " + gamma);
			//call.gammlabel.setText(String.valueOf(gamma));
			
	}
	
	protected void updateTrust() {
		// TODO Auto-generated method stub
		
		for(int j = 0 ;j<i;j++){	
			double tvalue;
			tvalue = reqPPS[j] - gamma*10;
			System.out.println("Tvalue["+j+"] = " + tvalue);
			if(tvalue>0){
				data[j][4]	= Double.parseDouble(data[j][4].toString())+tvalue;
				
			}else{
				data[j][4]	= Double.parseDouble(data[j][4].toString())/(1-tvalue);
				
			}
			System.out.println("Trust["+j+"]"+" = "+data[j][4].toString());
		}
		if(usage != 0)updateEntropy(usage);
		System.out.println("Updated Trust ");
	
		
	}
	protected void updateEntropy(double usage) {
		// TODO Auto-generated method stub
		double popj=0;
		double thisentropy = 0;
		

		//Status Active
		
		for(int j = 0;j<i;j++){
			
			if(reqPPS[j] != 0){
				popj = reqPPS[j]/usage;
				thisentropy = (-1)*(popj*(Math.log(popj)/Math.log(2)));
				data[j][5] = thisentropy ;
				//oldReq[j]=newReq[j];
			}
		}
		
	
		double totalentropy = 0;
		double devia = 0.0;
		double tempdevia = 0.0;
		double confi = 0.0 ;
		double avgentro =0.0;
		DecimalFormat df = new DecimalFormat("0.0000");
		
			for(int j =0;j<i;j++){
			System.out.println("Entropy["+j+"] " +data[j][5].toString() );
			totalentropy+= Double.parseDouble(data[j][5].toString()); // Xbar of Entropy
			}
			
		    avgentro = totalentropy/i;
	
			for(int j =0 ;j<i;j++){
				tempdevia += Math.pow((Double.parseDouble(data[j][5].toString())-(avgentro)),2);
			}
			
			devia = Math.sqrt(tempdevia/i);
			confi = 1.15*(devia/Math.sqrt(i));//25% = 0.32 ; 50% = 0.27 ; 75% = 1.15
			log_system_entropy = avgentro;
			log_system_deviation = devia;
			log_system_confidence = avgentro+confi;
//			call.systementropy.setText(String.valueOf(df.format(avgentro)));
//			call.deviation.setText(String.valueOf(df.format(devia)));
//			call.confidence.setText(String.valueOf(df.format(avgentro+confi)));
			checkflag();
		
	}

	
	protected void checkflag() {
		
		//Check Threshold
		if(flag ==0){
			double td = 0.22595617;
			for(int j=0 ; j<i;j++){
				if(Double.parseDouble(data[j][5].toString()) > td && Integer.parseInt(data[j][6].toString()) != -1){
					int temp = 0;
					temp = Integer.parseInt(data[j][6].toString())+1;
					data[j][6] = String.valueOf(temp);
				}	
				
			}
		}
		else{
			
			for(int j=0 ; j<i;j++){
				if(Integer.parseInt(data[j][6].toString()) > 3){
					data[j][6] = String.valueOf(-1);
				}	
				
			}
			
			for(int j=0 ; j<i;j++){
			
				if(Integer.parseInt(data[j][6].toString()) == -1)
					try {
						if(!log_atttker.contains(data[j][1].toString())){
							accessACL(data[j][1].toString());
							nub++;
							log_atttker += nub +". " + " "+data[j][1].toString()+"\n";
						}
					} catch (IOException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					} catch (JSONException e1) {
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
			}
			flag=0;
		}
			
	}
	
	public void accessACL(String badip) throws IOException, JSONException{
		
		URL object=new URL(url);
		HttpURLConnection con = (HttpURLConnection) object.openConnection();
		con.setDoOutput(true);
		con.setDoInput(true);
		con.setRequestProperty("Content-Type", "application/json");
		con.setRequestProperty("Accept", "application/json");
		con.setRequestMethod("POST");
		
		
		JSONObject rule = new JSONObject(); //created JSON Oblect
		rule.put("nw-proto", "TCP");
		rule.put("src-ip",badip+"/32");
		rule.put("dst-ip",victim+"/32");
		rule.put("action", "deny");


		OutputStreamWriter wr= new OutputStreamWriter(con.getOutputStream());
		wr.write(rule.toString());
		wr.flush();
		
		//get Response
		StringBuilder sb = new StringBuilder();  
		int HttpResult = con.getResponseCode(); 
		
		if(HttpResult == HttpURLConnection.HTTP_OK){
		    BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream(),"utf-8"));  
		    String line = null;  
		    while ((line = br.readLine()) != null) {  
		        sb.append(line + "\n");  
		    }  

		    br.close();  
		    System.out.println(""+sb.toString());  

		}
		else{
		    System.out.println(con.getResponseMessage());  
		}  
	}

	
	protected void greblog() {
		 try {
		    	
				File file = new File("/Users/Khantee/75s_Client10.txt");

				if (!file.exists()) {
					file.createNewFile();
				}
				FileWriter fw = new FileWriter(file.getAbsoluteFile());
				BufferedWriter bw = new BufferedWriter(fw);
				bw.write(log);
				bw.close();
				System.out.println("Done");
			}catch (IOException e) {
				e.printStackTrace();
			}
		
	}

		
	public static void main(String[] args) {
		// TODO Auto-generated method stub

	}

}
