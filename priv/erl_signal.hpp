class ErlSignal {
	public:
	chat *callback_module
	ErlSignal();
	~ErlSignal();

};

class TeraCrypto {
  private:
	  unsigned int d1[55], d2[57], d3[58];

	  int i1 = 0, i2 = 0, i3 = 0,
			  b1 = 0, b2 = 0, b3 = 0,
			  pos = 0;

	  unsigned int sum1 = 0, sum2 = 0, sum3 = 0,
			  sum = 0;

	public:
    TeraCrypto(const unsigned int* data);
	  void apply(unsigned char* data, unsigned int length);
    void print();	  
	private:
	  void next();
};
