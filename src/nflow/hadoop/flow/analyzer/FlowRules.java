package nflow.hadoop.flow.analyzer;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

import nflow.hadoop.flow.analyzer.FlowWritable.FIELDS;

import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.IOUtils;

public class FlowRules {
	
	private Map<String, Map> tcpRules = new HashMap<String, Map>();
	private Map<String, Map> udpRules = new HashMap<String, Map>();
	private Map<String, Map> icmpRules = new HashMap<String, Map>();

	public HashMap<String, Boolean> compileFilter(String strRuleFile) {
		// TODO Auto-generated method stub
	    BufferedReader in = null;
	    
	    try {
	      in = new BufferedReader(new InputStreamReader(new FileInputStream(strRuleFile)));
	      RuleParser parser;
	      String[] strfilters;
	      HashMap<String, Boolean> filters = new HashMap<String, Boolean>();
	      
	      String line;
	      while ((line = in.readLine()) != null) {
	    	  if(line.startsWith("#")) continue;
	    	  
	    	  strfilters = line.split("\\;");
	    	  for(String strfilter: strfilters)
	    		filters.put(strfilter, true);
	      }
	      return filters;
	      
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
	      IOUtils.closeStream(in);
	    }
		return null;
	}
	
	public HashMap<String, Boolean> compileAggregator(String strRuleFile) {
		// TODO Auto-generated method stub
	    BufferedReader in = null;
	    
	    try {
	      in = new BufferedReader(new InputStreamReader(new FileInputStream(strRuleFile)));
	      RuleParser parser;
	      String[] strfilters;
	      HashMap<String, Boolean> filters = new HashMap<String, Boolean>();
	      
	      String line;
	      while ((line = in.readLine()) != null) {
	    	  if(line.startsWith("#")) continue;
	    	  
	    	  strfilters = line.split("\\;");
	    	  for(String strfilter: strfilters)
	    		filters.put(strfilter, true);
	      }
	      return filters;
	      
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
	      IOUtils.closeStream(in);
	    }
		return null;
	}
	
	public void compileRules(String strRuleFile) {
		// TODO Auto-generated method stub
	    BufferedReader in = null;
	    
	    try {
	      in = new BufferedReader(new InputStreamReader(new FileInputStream(strRuleFile)));
	      RuleParser parser;
	      
	      String line;
	      while ((line = in.readLine()) != null) {
	    	  if(line.startsWith("#")) continue;
	    	  
	    	  parser = new RuleParser();
	    	  
	    	  if(parser.parse(line)) {
		        	if(parser.getProto()==6)
		        		tcpRules.put(parser.getRuleName(), parser.getRuleMap());
		        	else if(parser.getProto()==17)
		        		udpRules.put(parser.getRuleName(), parser.getRuleMap());
		        	else if(parser.getProto()==1)
		        		icmpRules.put(parser.getRuleName(), parser.getRuleMap());
	    	  }
	      }
	      
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
	      IOUtils.closeStream(in);
	    }
	}

	public Map<String, Map> getUdpRules() {
	    return Collections.unmodifiableMap(udpRules);
	}
	
	public Map<String, Map> getTcpRules() {
	    return Collections.unmodifiableMap(tcpRules);
	}

	public Map<String, Map> getIcmpRules() {
	    return Collections.unmodifiableMap(icmpRules);
	}
	
	/**
	 * Rule parser for single line
	 * @author yhlee
	 *
	 */
	class RuleParser{
		
		String ruleName = null;
		HashMap<FIELDS, ArrayList> ruleMap = new HashMap<FIELDS, ArrayList>();
		ArrayList<Long> orRuleAL = null;
		int proto = 0;
		
		private boolean parse(String line){
			String[] record = line.split("\\;");
			if(record.length<2)	return false;
			
			ruleName = record[0];
			
			/* parse one field rule */
			String[] arrRule = record[1].split("\\,");
			for(String rule: arrRule){
				String[] fieldRule = rule.split("\\=");
				if(fieldRule.length<2) return false;
				
				if(fieldRule[0].equals("proto")){
					this.setProto(Integer.parseInt(fieldRule[1]));
					continue;
				}
				
				/* parse RANGE rule */
				if(fieldRule[1].contains("-")){
					/* parse OR rule */
					String[] fieldOrRule = fieldRule[1].split("\\-");
					orRuleAL = new ArrayList<Long>();
					orRuleAL.add(-1L);
					for(String orRule: fieldOrRule)	{
						orRuleAL.add(Long.parseLong(orRule));
					}					
				}else{
					/* parse OR rule */
					String[] fieldOrRule = fieldRule[1].split("\\|");
					orRuleAL = new ArrayList<Long>();
					orRuleAL.add(1L);
					for(String orRule: fieldOrRule)	{
						orRuleAL.add(Long.parseLong(orRule));
					}
				}
				
				ruleMap.put(getFieldNo(fieldRule[0]),orRuleAL);
			}
			return true;
		}

		private FIELDS getFieldNo(String string) {
			// TODO Auto-generated method stub
			if(string.equals("srcport"))
				return FIELDS.SRCPORT;
			else if(string.equals("dstport"))
				return FIELDS.DSTPORT;
			else if(string.equals("proto"))
				return FIELDS.PROT;
			else if(string.equals("octets"))
				return FIELDS.DOCTETS;
			else if(string.equals("pkts"))
				return FIELDS.DPKTS;
			return null;
		}

		public String getRuleName() {
			// TODO Auto-generated method stub
			return ruleName;
		}

		public HashMap getRuleMap() {
			// TODO Auto-generated method stub
			return ruleMap;
		}

		public int getProto() {
			return proto;
		}

		public void setProto(int proto) {
			this.proto = proto;
		}

		public void setRuleName(String ruleName) {
			this.ruleName = ruleName;
		}

		public void setRuleMap(HashMap<FIELDS, ArrayList> ruleMap) {
			this.ruleMap = ruleMap;
		}
	}
}
