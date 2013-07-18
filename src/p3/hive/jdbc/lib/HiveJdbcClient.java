package p3.hive.jdbc.lib;

import java.io.IOException;
import java.sql.SQLException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.DriverManager;
import java.util.Calendar;

import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.Text;

public class HiveJdbcClient {
  
	private static String driverName = "org.apache.hadoop.hive.jdbc.HiveDriver";
    
	//"SELECT COUNT(DISTINCT df.addr) activeIPs FROM (SELECT SUBSTR(srcaddr,3,11) addr FROM daily_flows UNION ALL SELECT SUBSTR(dstaddr,3,11) addr FROM daily_flows) df ";              
	        
	private static void loadMySQLDriver(){
		try{
			Class.forName(driverName);
		}catch (Exception e){
			e.printStackTrace();
		}
	}
      	
	private Connection getMySQLConnection() throws SQLException{
		loadMySQLDriver();

		String url = "jdbc:hive://127.0.0.1:10000/default";
//		String url = "jdbc:hive://168.188.128.76:10000/default";
		String option ="";
		url = url + option;
		String id = "aaa";
		String passwd = "bbb";

		return DriverManager.getConnection(url, id, passwd);
	}
			
	public boolean createFlowStatsTables(){
        
        Connection con = null;
        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        try {
            con = getMySQLConnection();
            stmt = con.createStatement();

            sql = "  CREATE TABLE IF NOT EXISTS  flowstats "
                            + " (type STRING, aggrKey STRING, "
                            + " octets BIGINT, pkts BIGINT, flows BIGINT) "
                            + " PARTITIONED BY (area STRING, ds STRING, ts STRING)  " 
                            + " CLUSTERED BY(type) SORTED BY(aggrKey) INTO 32 BUCKETS "
                            + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                            + " STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);
            
            /* total volume */
            sql = "  CREATE TABLE IF NOT EXISTS  totalvolume "
                    + " (ts STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
		    
		    /* protocol */
            sql = "  CREATE TABLE IF NOT EXISTS  totalprotocol "
                    + " (ts STRING, protocol STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) SORTED BY(protocol) INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
		    
		    /* AS */
            sql = "  CREATE TABLE IF NOT EXISTS  asegress "
                    + " (ts STRING, asn STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) SORTED BY(asn)  INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
		    
            sql = "  CREATE TABLE IF NOT EXISTS  asingress "
                    + " (ts STRING, asn STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) SORTED BY(asn)  INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
		    
		    
		    /* Protocol */
            sql = "  CREATE TABLE IF NOT EXISTS  subnetegress "
                    + " (ts STRING, subnet STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) SORTED BY(subnet)  INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
		    
            sql = "  CREATE TABLE IF NOT EXISTS  subnetingress "
                    + " (ts STRING, subnet STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) SORTED BY(subnet)  INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
		    
		    /* protocol */
            sql = "  CREATE TABLE IF NOT EXISTS  portegress "
                    + " (ts STRING, port STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) SORTED BY(port)  INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
		    
            sql = "  CREATE TABLE IF NOT EXISTS  portingress "
                    + " (ts STRING, port STRING, octets BIGINT, pkts BIGINT, flows BIGINT) "
                    + " PARTITIONED BY (area STRING, month STRING, ds STRING)  " 
                    + " CLUSTERED BY(ts) SORTED BY(port)  INTO 32 BUCKETS "
                    + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' "
                    + " STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
    
		    } catch (SQLException e) {
		        // TODO Auto-generated catch block
		        e.printStackTrace();
		
		}finally{			
		        try {
		                if(rs!=null) rs.close();
		                if(stmt!=null) stmt.close();
		                if(con!=null) con.close();
		        } catch (SQLException e) {
		                // TODO Auto-generated catch block
		                e.printStackTrace();
		        }
		}		
		return true;
	}
	
	public boolean createFlowTables(){
        
        Connection con = null;
        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        try {
            con = getMySQLConnection();
            stmt = con.createStatement();
            
            /* daily_flows */
            sql = "  CREATE TABLE IF NOT EXISTS  daily_flows "
                            + "(sys_uptime bigint, " +
                            "time_stamp bigint, srcaddr string, dstaddr string, nexthop string, input int, " +
                            "output int, dpkts bigint, doctets bigint, first_time double, last_time double, " +
                            "srcport int, dstport int, pad1 int, tcp_flags int, prot int, tos int, src_as int, " +
                            "dst_as int, src_mask int, dst_mask int, pad2 int, orderby string  ) " +
                            "PARTITIONED BY (area STRING, ds STRING, ts STRING)  " +
//                            " SORTED BY time_stamp "  +                         
                            "ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
                            "STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);
            
            /* koren_subnet */
            sql = "  CREATE TABLE IF NOT EXISTS  koren_subnet "
                    + "(organ STRING, asn STRING, prefix STRING) " +
                    "PARTITIONED BY (area STRING)  " +                 
                    "ROW FORMAT DELIMITED  FIELDS TERMINATED BY '|' " +
                    "STORED AS TEXTFILE";
		    System.out.println("Running: " + sql);
		    stmt.executeQuery(sql);
            
            /* spoofs */
            sql = " CREATE TABLE IF NOT EXISTS  spoofs "
                            + "(srcaddr STRING, dstaddr STRING, ts STRING) " +
                            "PARTITIONED BY (area STRING, month STRING, ds STRING)  " +
                            "ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
//                            "CLUSTERED BY (srcaddr) SORTED BY (dstaddr) " +
                            "STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);

            /* scan */
            sql = " CREATE TABLE IF NOT EXISTS  scan "
                            + "(srcaddr STRING, dstaddr STRING, cnt INT, ts string) " +
                            "PARTITIONED BY (area STRING, month STRING, ds STRING)  " +
                            "ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
//                            "CLUSTERED BY (inout) SORTED BY ds " +
                            "STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);

            /* active IP list */
//            stmt.executeQuery("DROP TABLE activeIP");
            sql = " CREATE TABLE IF NOT EXISTS  activeIP "
                            + "(ipaddr STRING, ts STRING) " +
                            "PARTITIONED BY (area STRING, month STRING, ds STRING)  " +
                            "ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
                            "STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);

            /* active IP cnt */
//            stmt.executeQuery("DROP TABLE activeIPCnt");
            sql = " CREATE TABLE IF NOT EXISTS  activeIPCnt "
                            + "(ds STRING, cnt INT) " +
                            "PARTITIONED BY (area STRING, month STRING)  " +
                            "ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
                            "STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);

            /* active Subnet list */
//            stmt.executeQuery("DROP TABLE activeSubnet");
            sql = " CREATE TABLE IF NOT EXISTS  activeSubnet "
                            + "(ipaddr STRING) " +
                            "PARTITIONED BY (area STRING, month STRING, ds STRING)  " +
                            "ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
                            "STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);

            /* heavy user list */
//            stmt.executeQuery("DROP TABLE heavyUser");
            sql = " CREATE TABLE IF NOT EXISTS  heavyUser "
                            + "(ipaddr STRING, volume BIGINT, ts STRING) " +
                            "PARTITIONED BY (area STRING, month STRING, ds STRING)  " +
                            "ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
                            "STORED AS TEXTFILE";
            System.out.println("Running: " + sql);
            stmt.executeQuery(sql);

        } catch (SQLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();

        }finally{			
                try {
                        if(rs!=null) rs.close();
                        if(stmt!=null) stmt.close();
                        if(con!=null) con.close();
                } catch (SQLException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                }
        }		
        return true;
	}
	
    public void analysisFlowAnomaly(String area, String ds, String ts){
    	
        Connection con = null;
        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;
        String month = null;
        
        if(ds == null){
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(System.currentTimeMillis());	
            ds = String.format("%1$tY-%1$tm-%1$td", cal);
        }
        month = ds.substring(0,7);
        
    try {
        con = getMySQLConnection();
        stmt = con.createStatement();
        
        /* scan */
        sql = "INSERT INTO TABLE scan PARTITION(area='koren', month = '"+month+"', ds='"+ds+"') "
                + " SELECT df.srcaddr, df.dstaddr, df.cnt, ts FROM "
                + " (SELECT df.srcaddr, df.dstaddr, COUNT(DISTINCT df.dstport) cnt, MIN(ts) ts"
                + " FROM daily_flows df WHERE ds='"+ds+"'  AND ts='"+ts+"' GROUP BY df.srcaddr, df.dstaddr) df WHERE df.cnt > 10 ";

        System.out.println("Running: " + sql);
        stmt.executeQuery(sql);
        
        /* spoofs */
        sql = "INSERT INTO TABLE spoofs PARTITION(area='koren', month = '"+month+"', ds='"+ds+"') "
        		+ " SELECT ds.* "
                + " FROM (SELECT d.srcaddr srcaddr, d.src_as d_asn, s.asn s_asn "
                + "			FROM daily_flows d LEFT OUTER JOIN koren_subnet s ON (d.srcaddr = s.subnet)" 
        		+ "			WHERE d.area='koren' AND ds='"+ds+"' AND ts='"+ts+"') ds" 
        		+ " WHERE ds.srcaddr = null OR ds.d_asn <> ds.s_asn ";

        System.out.println("Running: " + sql);
//        stmt.executeQuery(sql);
        
        /* active IP */
/*
        sql = "INSERT INTO TABLE activeIP PARTITION(ds='"+ds+"',area='cnu')"
                + " SELECT DISTINCT df.addr ipaddr FROM (SELECT srcaddr addr FROM daily_flows  WHERE (srcaddr LIKE '\\'/168.188%'  AND ds='"+ds+"' AND ts='"+ts+"') "
                + " UNION ALL SELECT dstaddr addr FROM daily_flows  WHERE (dstaddr LIKE '\\'/168.188%'  AND ds='"+ds+"' AND ts='"+ts+"')) df";

        System.out.println("Running: " + sql);
        stmt.executeQuery(sql);
       
        
        String activeIPinCSE = "INSERT INTO TABLE activeIP PARTITION(ds='"+ds+"', area='cse')"
                + " SELECT ipaddr FROM activeIP  WHERE ((ipaddr LIKE '\\'/168.188.126%' OR ipaddr LIKE '\\'/168.188.127%' OR ipaddr LIKE '\\'/168.188.128%')  AND ds='"+ds+"' AND ts='"+ts+"')  ";   

        String activeIPCnt = "INSERT INTO TABLE activeIPCnt PARTITION(area='cnu')"
                + " SELECT  ds, COUNT(ipaddr) FROM  activeIP WHERE (ds='"+ds+"' AND area='cnu')  GROUP BY ds ";

        String activeIPCntinCSE = "INSERT INTO TABLE activeIPCnt PARTITION(area='cse')"
                + " SELECT  ds, COUNT(ipaddr) FROM  activeIP WHERE (ds='"+ds+"' AND area='cse') GROUP BY ds ";

        String heavyUser = " INSERT INTO TABLE heavyUser PARTITION(ds='"+ds+"')"
                + " SELECT df.addr ipaddr, SUM(df.doctets) summary FROM (SELECT srcaddr addr, doctets FROM daily_flows  WHERE area='koren' AND ds='"+ds+"' "
                + " UNION ALL SELECT dstaddr addr, doctets FROM daily_flows  WHERE area='koren' AND ds='"+ds+"') df GROUP BY df.addr ORDER BY summary DESC ";
      
        String activeSubnet = " INSERT INTO TABLE activeSubnet PARTITION(ds='"+ds+"')"
                + " SELECT DISTINCT SUBSTR(df.addr,3,11) ipaddr FROM (SELECT srcaddr addr FROM daily_flows  WHERE (srcaddr LIKE '\\'/168.188%') "
                + " UNION ALL SELECT dstaddr addr FROM daily_flows  WHERE (dstaddr LIKE '\\'/168.188%')) df ";
  */
            
        } catch (SQLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();			
        }finally{			
                try {
                        if(rs!=null) rs.close();
                        if(stmt!=null) stmt.close();
                        if(con!=null) con.close();
                } catch (SQLException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                }
        }		
        return;
    }

    public void analysisFlowStatsData(String area, String ds, String ts){
		
        Connection con = null;
        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;
        String month = null;
                   
        if(ds == null){
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(System.currentTimeMillis());	
            ds = String.format("%1$tY-%1$tm-%1$td", cal);
        }
        month = ds.substring(0,7);
        
    try {
        con = getMySQLConnection();
        stmt = con.createStatement();

        sql = "FROM flowstats fs"
        		
        		+ " INSERT INTO TABLE totalvolume PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
                + " SELECT  ts, octets, pkts, flows " 
                + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='totalVolume' AND aggrkey='all' "
                
				+ " INSERT INTO TABLE totalprotocol PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
		        + " SELECT  ts , aggrkey, octets, pkts, flows " 
		        + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='totalProtocol' "
		                        
				+ " INSERT INTO TABLE portegress PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
		        + " SELECT  ts , aggrkey, octets, pkts, flows " 
		        + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='srcPort' "
		                        
				+ " INSERT INTO TABLE portingress PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
		        + " SELECT  ts , aggrkey, octets, pkts, flows " 
		        + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='dstPort' "
		                        
				+ " INSERT INTO TABLE subnetegress PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
		        + " SELECT  ts , aggrkey, octets, pkts, flows " 
		        + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='srcSubnet' "
		                        
				+ " INSERT INTO TABLE subnetingress PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
		        + " SELECT  ts , aggrkey, octets, pkts, flows " 
		        + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='dstSubnet' "
		                        
				+ " INSERT INTO TABLE asegress PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
		        + " SELECT  ts , aggrkey, octets, pkts, flows " 
		        + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='srcAs' "
		                        
				+ " INSERT INTO TABLE asingress PARTITION(area='"+area+"', month='"+month+"', ds='"+ds+"')"
		        + " SELECT  ts , aggrkey, octets, pkts, flows " 
		        + " WHERE area='"+area+"' AND ds='"+ds+"' AND ts='"+ts+"' AND type='dstAs' ";

        System.out.println("Running: " + sql);
        stmt.executeQuery(sql);

        } catch (SQLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();			
        }finally{			
                try {
                        if(rs!=null) rs.close();
                        if(stmt!=null) stmt.close();
                        if(con!=null) con.close();
                } catch (SQLException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                }
        }		
        return;
	}
    
    public void loadToHive(String tablename, String inpath, String area, String ds, String ts){
		
        Connection con = null;
        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;
                   
        if(ds == null){
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(System.currentTimeMillis());	
            ds = String.format("%1$tY-%1$tm-%1$td", cal);
        }
        
    try {
        con = getMySQLConnection();
        stmt = con.createStatement();
        
        if(inpath==null)   inpath = "flow_print";
        
        sql = "load data inpath '" + inpath + "' "+
                        " into table " + tablename +
                        " partition (area='"+area+"', ds='"+ds+"', ts='"+ts+"')";
  	
        System.out.println("Running: " + sql);
        stmt.executeQuery(sql);
            
        } catch (SQLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();			
        }finally{			
                try {
                        if(rs!=null) rs.close();
                        if(stmt!=null) stmt.close();
                        if(con!=null) con.close();
                } catch (SQLException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                }
        }		
        return;
  	}
    
	public void loadFlowData(String tablename, String inPath, String area, String ds, String ts) throws IOException {
	  
		Path inputPath = new Path(inPath);
		FileSystem fs = FileSystem.get(new Configuration());
		FileStatus stat = fs.getFileStatus(inputPath);
		
		if(stat.isDir()){
			FileStatus[] stats = fs.listStatus(inputPath);
			for(FileStatus curfs : stats){
				if(!curfs.isDir())
					  loadToHive(tablename, curfs.getPath().toUri().getPath(), area, ds, ts);
			}
		}else{
			 loadToHive(tablename, stat.getPath().toUri().getPath(), area, ds, ts);
		}
		fs.close();
	}
    
    
	private boolean createNHNTable(String tablename){
        
        Connection con = null;
        Statement stmt = null;
        ResultSet rs = null;
        String sql = null;

        try {
            con = getMySQLConnection();
            stmt = con.createStatement();
            
            if(tablename.equals("httplog")){
                sql = " CREATE TABLE IF NOT EXISTS " + tablename
                                + " (srcaddr string, dstaddr string, srcport int, dstport int, first_time double,"
                                + " method string, host string, message string, referrer string, contentLength string,"
                                + " contentType string, server string, user_agent string, accept string, accept_encoding string,"
                                + " firstkey string, secondkey string  ) "
                                + " PARTITIONED BY (ds STRING, ts STRING)  "
                                + " CLUSTERED BY(srcaddr) SORTED BY(first_time) INTO 32 BUCKETS "
                                + " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '\\001' "
                                + " STORED AS SEQUENCEFILE";
                System.out.println("Running: " + sql);
                stmt.executeQuery(sql);
         
            }else if(tablename.equals("userurls")){
	                sql = " CREATE TABLE IF NOT EXISTS " + tablename
	                                + " (srcaddr string, urls string ) " +
	                                " PARTITIONED BY (ds STRING)  " +
	                                " ROW FORMAT DELIMITED  FIELDS TERMINATED BY '\t' " +
	                                " STORED AS TEXTFILE";
	                System.out.println("Running: " + sql);
	                stmt.executeQuery(sql);
	                
            }else if(tablename.equals("urlusersviews")){
	                sql = " CREATE TABLE IF NOT EXISTS " + tablename
	                                + "(urls string, users int, views int  ) " +
	                                " PARTITIONED BY (ds STRING)  " +
	                                " ROW FORMAT DELIMITED  FIELDS TERMINATED BY ',' " +
	                                " STORED AS TEXTFILE ";
	                System.out.println("Running: " + sql);
	                stmt.executeQuery(sql);
        	}

        } catch (SQLException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();

        }finally{			
                try {
                        if(rs!=null) rs.close();
                        if(stmt!=null) stmt.close();
                        if(con!=null) con.close();
                } catch (SQLException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                }
        }		
        return true;
	}
	private boolean load_NHNData(String tablename, String inpath, String ds){
		
		Connection con = null;
		Statement stmt = null;
		ResultSet rs = null;
		String sql = null;
                        
        if(ds == null){
            Calendar cal = Calendar.getInstance();
            cal.setTimeInMillis(System.currentTimeMillis());	
            ds = String.format("%1$tY-%1$tm-%1$td", cal);
        }
        
		try {
			con = getMySQLConnection();
			stmt = con.createStatement();
			
			createNHNTable(tablename);

			sql = "load data inpath '" + inpath + "' "+
				" into table " + tablename +
				" partition(ds='"+ds+"')";
			
			System.out.println("Running: " + sql);
			rs = stmt.executeQuery(sql);			
			if(rs == null) return false;
			
		} catch (SQLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			
		}finally{			
			try {
				if(rs!=null) rs.close();
				if(stmt!=null) stmt.close();
				if(con!=null) con.close();
			} catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}		
		return true;
	}

  /**
 * @param args
 * @throws IOException 
 * @throws SQLException
   */
  public void loadTableData(String tablename, String inpath, String area, String ds, String ts) throws IOException {
	  
//	  ts = ts.substring(0,2)+":"+ts.substring(2);
	  
	  if(ds==null){
	      Calendar cal = Calendar.getInstance();
	      cal.setTimeInMillis(System.currentTimeMillis());	
	      ds = String.format("%1$tY-%1$tm-%1$td", cal);
	      ts = String.format("%1$tY-%1$tm-%1$td %1$tH:%1$tM:%1$tS", cal);
	  }
	  
	  if(tablename.equals("httplog")){
		  load_NHNData("httplog", "HttpReassemble_out"+"/"+ds, ds);
		  load_NHNData("userurls", "UserUrls_out"+"/"+ds, ds);
		  load_NHNData("urlusersviews", "UrlUsersViewsClicks_out"+"/"+ds, ds);
		  
	  }else if(tablename.equals("daily_flows")){
		  System.out.println("loading "+ tablename + ":"+area+":"+ds+":"+ts);
		  createFlowTables();
		  loadFlowData(tablename, inpath, area, ds, ts);
		  analysisFlowAnomaly(area, ds, ts);
		  
	  }else if(tablename.equals("flowstats")){
		  System.out.println("loading "+ tablename +":"+area+":"+ds+":"+ts);
		  createFlowStatsTables();
		  loadFlowData(tablename, inpath, area, ds, ts);
		  analysisFlowStatsData(area, ds, ts);
	  }
	  
  }
	  
	
  /**
 * @param args [tablename] [src] [ds] [ts]
 * @throws SQLException
 * @throws IOException 
   */
  public static void main(String[] args) throws SQLException, IOException {
	  
	  String ds = null;	  
	  String ts = null;
	  String inpath = null;
	  
	  String tablename = args[0];
	  System.out.println(tablename);
	  	  
	  if(args.length>2){ 
		  inpath = args[1];
	  }
	  if(args.length==4){
		  ds = args[2];
		  ts = args[3];
	  }	  	  
	  new HiveJdbcClient().loadTableData(tablename, inpath, "koren", ds, ts);	  
  }
}
