package net.floodlightcontroller.hybrid;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.table.DefaultTableModel;



public class HybridGUI extends JFrame implements ActionListener {
	
	private static final long serialVersionUID = 1L;
	protected JPanel panel, paneltop,panelcen,panelbot,panelen,g1,g1_2,g1all,g2,g2all,g3,g4;
	protected JLabel gammlabel,systementropy;
	protected JTextField threshold;
	protected JScrollPane scrollPane;
	protected JLabel title,label1,label2,label3,label4,label5,label6,deviation,confidence,stat;
	protected JButton button;
	protected DefaultTableModel model;
	protected JTable table;
	
	String[] columnNames = {"No",
			"IP Address",
	        "MAC Address",
	        "Request times",
	        "TurstV",
	        "Entropy",
	        "flag"};
	//HybridApp call = new HybridApp();
	protected void setgui() {
		
		setContentPane(panel);
		setSize(800,600);
		setLocation(300,100);
		setVisible(true);
	}
	
	protected void creategui(Object data[][] ) {

		panel = new JPanel(new BorderLayout());
		paneltop = new JPanel();
		panelcen = new JPanel(new FlowLayout());
		panelbot = new JPanel(new FlowLayout());
		panelen = new JPanel(new FlowLayout());
		g1 = new JPanel(new FlowLayout());
		g1_2 = new JPanel(new FlowLayout());
		g1all = new JPanel(new FlowLayout());
		g2 = new JPanel(new FlowLayout());
		g2all = new JPanel(new FlowLayout());
		g3 = new JPanel(new GridLayout(2,1));
		g4 = new JPanel(new FlowLayout());
		gammlabel =new JLabel("0.0");
		systementropy = new JLabel("0.0");
		threshold = new JTextField("1",10);
		scrollPane = new JScrollPane();
		title = new JLabel("Show List Clients");
		label1 = new JLabel("Gamma: ");
		label2 = new JLabel("Status: ");
		label3 = new JLabel("Mean: ");
		label4 = new JLabel("Threshold: ");
		label5 = new JLabel("Deviation: ");
		label6 = new JLabel("Max Confidence: ");
		deviation =  new JLabel("0.00");
		confidence = new JLabel("0.00"); 
		stat = new JLabel("Active");
		button = new JButton("Start");
		table = new JTable();
		paneltop.setLayout(new BorderLayout());
		stat.setForeground(Color.GREEN);
		title.setBorder(BorderFactory.createEmptyBorder(10, 300, 0, 0));
		title.setFont(new Font("Serif", Font.PLAIN, 18));
		paneltop.add(title , BorderLayout.NORTH);
		g1.add(label1);
		g1.add(gammlabel);
		g1_2.add(label4);
		g1_2.add(threshold);
		g1all.add(g1);
		g1all.add(g1_2);
		g2.add(label2);
		g2.add(stat);
		g2all.add(g2);
		g2all.add(button);
		g3.add(g1all);
		g3.add(g2all);
		g4.add(label3);
		g4.add(systementropy);
		g4.add(label5);
		g4.add(deviation);
		g4.add(label6);
		g4.add(confidence);
		panelen.add(g4);
		paneltop.add(g3 ,  BorderLayout.CENTER);
		
		table.setAutoCreateRowSorter(true);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		model = new DefaultTableModel(data,columnNames);
        table.setModel(model);
        scrollPane.setPreferredSize(new Dimension(700, 500));
		scrollPane.add(table);
		scrollPane.setViewportView(table);
		panelbot.add(scrollPane);
		
		
		panel.add(paneltop, BorderLayout.NORTH);
		panel.add(panelbot, BorderLayout.CENTER);
		panel.add(g4, BorderLayout.AFTER_LAST_LINE);
		
		
		button.addActionListener(this);	
	}


	void updatateTable(Object data[][]){
		model = new DefaultTableModel(data,columnNames);
        table.setModel(model);
		model.fireTableDataChanged();
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		Object ob = e.getSource();
		if(ob.equals(button)){
			
		HybridApp.flag = 1;
		stat.setText("Killing");	
		stat.setForeground(Color.RED);		
		}
		
	}
	


	
	
	
}
