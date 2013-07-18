package nflow.hadoop.flow.analyzer;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;

import nflow.hadoop.flow.analyzer.FlowWritable.FIELDS;

import org.apache.hadoop.io.IOUtils;

public class RuleCompiler {
	
	enum CountType {UNIQUE, COUNT};
	enum Operator  {ADD, SUB, MUL, DIV, NOP, BOUND, OR};
	
	private HashMap<String, Rule> rules;

	public RuleCompiler() {
		super();
		// TODO Auto-generated constructor stub
		rules = new HashMap<String, Rule>();
	}
	
	public void compile(String strRuleFile) {
		// TODO Auto-generated method stub
	    BufferedReader in = null;
	    
	    try {
	      in = new BufferedReader(new InputStreamReader(new FileInputStream(strRuleFile)));
	      
	      String line;
	      while ((line = in.readLine()) != null) {
	    	  if(line.startsWith("#")) continue;
	    	  if(line.trim().length()==0) continue;
	    	  Rule rule = new Rule();
	    	  rule.compile(line);
	    	  rules.put(rule.name, rule);
	      }	      
	    } catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} finally {
	      IOUtils.closeStream(in);
	    }
	}
	
	
	public ArrayList<Pattern> compilePatterns(String string){
		
		ArrayList<Pattern> patterns = new ArrayList<Pattern>();
		if(string.equals("null")) return null;
		
		String[] items = string.split("\\,");
		Pattern pattern;
		
		for(String item: items){				
			pattern = new Pattern();
			pattern.compile(item);
			patterns.add(pattern);
		}
		return patterns;
	}

	public Rule getRule(String rulename) {
		// TODO Auto-generated method stub
		return rules.get(rulename);
	}
	
	public void setRules(HashMap<String, Rule> rules) {
		this.rules = rules;
	}
	
	public HashMap<String, Rule> getRules() {
		// TODO Auto-generated method stub
		return rules;
	}


	/**
	 * Pattern for matching (syn/fin=1.2-)
	 * @author yhlee
	 *
	 */
	class Pattern{
		Operator lop;
		ArrayList<FIELDS> lh = null; // operator|left|rigtht
		Operator rop;
		ArrayList<Long> rh = null;   // value
		
		public Pattern() {
			super();
			// TODO Auto-generated constructor stub
			lh = new ArrayList<FIELDS>();
			rh = new ArrayList<Long>();
		}
		
		public Pattern compile(String string){
			/* parse one field rule */
			String[] items = string.split("\\,");
						
			for(String item: items){
				
				String[] strPattern = item.split("\\=");
/*				
				if(strPattern.length<2){
					lop = Operator.NOP;
					lh.add(FlowWritable.getFieldNo(items[0]));
					continue;
				}
*/				
				/* left-hand */
				String[] strFields = null;
				if(strPattern[0].contains("+")){
					strFields = strPattern[0].split("+");
					lop = Operator.ADD;
					
				}else if(strPattern[0].contains("-")){
					strFields = strPattern[0].split("-");
					lop = Operator.SUB;
					
				}else if(strPattern[0].contains("*")){
					strFields = strPattern[0].split("*");
					lop = Operator.MUL;
					
				}else if(strPattern[0].contains("/")){
					strFields = strPattern[0].split("/");
					lop = Operator.DIV;
					
				}else{
					strFields = new String[1];
					strFields[0] = strPattern[0];
					lop = Operator.NOP;
				}
				
				lh.add(FlowWritable.getFieldNo(strFields[0]));
				if(strFields.length>1)
					lh.add(FlowWritable.getFieldNo(strFields[1]));
				
				
				/* right-hand */
				if(strPattern[1].contains("-")){
					/* parse Boundary rule */
					String[] boundaries = strPattern[1].split("\\-");
					rh.add(Long.parseLong(boundaries[0]));
					if(boundaries.length == 1)
						rh.add(Long.MAX_VALUE);
					else
						rh.add(Long.parseLong(boundaries[1]));		
					rop = Operator.BOUND;
					
				}else if(strPattern[1].contains("|")){
					/* parse Boundary rule */
					String[] boundaries = strPattern[1].split("\\|");
					rh.add(Long.parseLong(boundaries[0]));
					rh.add(Long.parseLong(boundaries[1]));		
					rop = Operator.OR;
					
				}else{
					rh.add(Long.parseLong(strPattern[1]));
					rop = Operator.NOP;
				}
			}
			return null;
		}

		public boolean matchPatterns(FlowWritable fw) throws UnknownHostException {
			// TODO Auto-generated method stub
			Long lh_value = 0L;
			switch (lop)
			{
			case NOP:
				lh_value = fw.getFieldValue(lh.get(0)); // lh.get(0));
				break;
			case ADD:
				lh_value = fw.getFieldValue(lh.get(0)) + fw.getFieldValue(lh.get(1));
				break;
			case SUB:
				lh_value = fw.getFieldValue(lh.get(0)) - fw.getFieldValue(lh.get(1));
				break;
			case MUL:
				lh_value = fw.getFieldValue(lh.get(0)) * fw.getFieldValue(lh.get(1));
				break;
			case DIV:
				lh_value = fw.getFieldValue(lh.get(0)) / fw.getFieldValue(lh.get(1));
				break;
			default:
				return false;
			}
			
			switch (rop)
			{
			case NOP:
				if(lh_value == rh.get(0)) return true;
				break;
			case BOUND:
				if(lh_value >= rh.get(0) && lh_value <= rh.get(1)) return true;
				break;
			case OR:
				for(Long rhVal : rh)
					if(lh_value == rhVal) return true;
				break;
			}				
			return false;
		}

		public boolean detectPatterns(long[] count) {
			// TODO Auto-generated method stub
			Long lh_value = 0L;
			switch (lop)
			{
			case NOP:
				lh_value = count[0];
				break;
			case ADD:
				lh_value = count[0] + count[1];
				break;
			case SUB:
				lh_value = count[0] - count[1];
				break;
			case MUL:
				lh_value = count[0] * count[1];
				break;
			case DIV:
				lh_value = count[0] / count[1];
				break;
			default:
				return false;
			}
				
			switch (rop)
			{
			case NOP:
				if(lh_value == rh.get(0)) return true;
				break;
			case BOUND:
				if(lh_value >= rh.get(0) && lh_value <= rh.get(1)) return true;
				break;
			case OR:
				for(Long rhVal : rh)
					if(lh_value == rhVal) return true;
				break;
			}				
			return false;
		}

		public Operator getLop() {
			return lop;
		}

		public void setLop(Operator lop) {
			this.lop = lop;
		}

		public ArrayList<FIELDS> getLh() {
			return lh;
		}

		public void setLh(ArrayList<FIELDS> lh) {
			this.lh = lh;
		}

		public Operator getRop() {
			return rop;
		}

		public void setRop(Operator rop) {
			this.rop = rop;
		}

		public ArrayList<Long> getRh() {
			return rh;
		}

		public void setRh(ArrayList<Long> rh) {
			this.rh = rh;
		}

		@Override
		public String toString() {
			
			String retval = "Pattern [lop=" + this.lop;
						
			retval += ", lh=" ;	
			
			for(FIELDS field : lh)
				retval += "|" + field;
	
			retval += ", rop=" + rop;
					
			retval += ", rh=";
			
			for(Long field : rh)
				retval += "|" + field;
									

			return retval;	
		}
		
		
	}
	
	/**
	 * Rule Class
	 * @author yhlee
	 * Rule structure => attackname;binsize;filtering_pattern;groupby;sortby;unique/count;detection_pattern
	 */
	class Rule{
		String name;
		int binsize;
		ArrayList<Pattern> filter;
		ArrayList<FIELDS> sortby;
		ArrayList<FIELDS> groupby;
		CountType counttype;
		ArrayList<Pattern> detector;	
		ArrayList<FIELDS> retvals;
		
		public Rule() {
			super();
			// TODO Auto-generated constructor stub
			filter = new ArrayList<Pattern>();
			detector = new ArrayList<Pattern>();
			groupby = new ArrayList<FIELDS>();
			sortby = new ArrayList<FIELDS>();
			retvals = new ArrayList<FIELDS>();
		}
		

		/*
		 * parse rule
		 *   => attackname;binsize;filtering_pattern;groupby;sortby;unique/count;detection_pattern
		 *   => e.g. port_scan;300;ip,proto=6;srcip,dstip;dstport;unique;pkts=20-;sip,dip
		 */
		private void compile(String line){
			
			String[] record = line.split("\\;");
			if(record.length<3)	return;
			
			name = record[0];
			binsize = Integer.parseInt(record[1]);		
			filter = compilePatterns(record[2]);
					
			String[] groupbykey = record[3].split("\\,");
			for(String key: groupbykey)
				groupby.add(FlowWritable.getFieldNo(key));
			
			String[] sortbykey = record[4].split("\\,");
			for(String key: sortbykey)
				sortby.add(FlowWritable.getFieldNo(key));		
					
			counttype = record[5].equals("unique") ? CountType.UNIQUE: CountType.COUNT;
			detector = compilePatterns(record[6]);

			String[] retvalskey = record[4].split("\\,");
			for(String key: retvalskey)
				retvals.add(FlowWritable.getFieldNo(key));		
		}

		public boolean matchMapRule(FlowWritable fw) throws UnknownHostException {
			// TODO Auto-generated method stub
			if(filter==null) return true;
			for(Pattern pattern : filter){
				if(!pattern.matchPatterns(fw))	return false;
			}
			return true;
		}
		
		public boolean matchReduceRule(long[] counts) {
			// TODO Auto-generated method stub
			if(detector==null) return true;
			for(Pattern pattern : detector){
				if(!pattern.detectPatterns(counts))	return false;
			}
			return true;
		}
		
		public String getName() {
			return name;
		}

		public void setName(String name) {
			this.name = name;
		}

		public int getBinsize() {
			return binsize;
		}

		public void setBinsize(int binsize) {
			this.binsize = binsize;
		}

		public ArrayList<Pattern> getFilter() {
			return filter;
		}

		public void setFilter(ArrayList<Pattern> filter) {
			this.filter = filter;
		}

		public ArrayList<FIELDS> getSortby() {
			return sortby;
		}

		public void setSortby(ArrayList<FIELDS> sortby) {
			this.sortby = sortby;
		}

		public ArrayList<FIELDS> getGroupby() {
			return groupby;
		}

		public void setGroupby(ArrayList<FIELDS> groupby) {
			this.groupby = groupby;
		}

		public CountType getCounttype() {
			return counttype;
		}

		public void setCounttype(CountType counttype) {
			this.counttype = counttype;
		}

		public ArrayList<Pattern> getDetector() {
			return detector;
		}

		public void setDetector(ArrayList<Pattern> detector) {
			this.detector = detector;
		}

		public ArrayList<FIELDS> getRetvals() {
			return retvals;
		}

		public void setRetvals(ArrayList<FIELDS> retvals) {
			this.retvals = retvals;
		}


	
		@Override
		public String toString() {
			
			String filter = null; 
			for(Pattern pattern : this.filter)
				filter += "|" + pattern.toString();
					
			String detector = null; 
			for(Pattern pattern : this.detector)
				detector += "|" + pattern.toString();
					
			return "Rule [name=" + name + ", binsize=" + binsize + ", filter="
					+ filter + ", sortby=" + sortby + ", groupby=" + groupby
					+ ", counttype=" + counttype + ", detector=" + detector
					+ ", retvals=" + retvals + "]";
		}
		
		
	}
}
