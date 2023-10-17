#include <iostream>
#include <map>

class MapValueBase {
 public:
	virtual ~MapValueBase() {}
};

class SingleStringValue : public MapValueBase{
 public:
	SingleStringValue() {}
	SingleStringValue(const std::string &value) :  _value(value) {}
	virtual~SingleStringValue() {}
	virtual std::string get_value() { return _value; }

 private:
	std::string _value;
};

class MultiStringValue : public MapValueBase{
 public:
	MultiStringValue(const std::string &value1,
					 const std::string &value2) : _value1(value1),
												  _value2(value2) {}
	virtual~MultiStringValue() {}
	std::string get_value1() { return _value1; }
	std::string get_value2() { return _value2; }

 private:
	std::string _value1;
	std::string _value2;
};

class NumValue : public MapValueBase {
 public:
	NumValue(int num) : _value(num) {}
	virtual ~NumValue() {}
	int get_value() { return _value; }

 private:
	int _value;
};

void print_value(const std::string &key, MapValueBase *value) {
	if (key == "single") {
		SingleStringValue *ptr = dynamic_cast<SingleStringValue *>(value);
		std::cout << "single: value=" << ptr->get_value() << std::endl;
	} else if (key == "multi") {
		MultiStringValue *ptr = dynamic_cast<MultiStringValue *>(value);
		std::cout << "multi: value1=" << ptr->get_value1() << std::endl;
		std::cout << "       value2=" << ptr->get_value2() << std::endl;
	} else {
		NumValue *ptr = dynamic_cast<NumValue *>(value);
		std::cout << "num: value=" << ptr->get_value() << std::endl;

	}
}

int main() {
	std::map<std::string, MapValueBase> test_map;
	std::map<std::string, MapValueBase>::iterator itr;

	test_map["single"] = SingleStringValue("test_single");
	test_map["multi"] = MultiStringValue("test_multi1", "test_multi2");
	test_map["num"] = NumValue(42);

	for (itr = test_map.begin(); itr != test_map.end(); ++itr) {
		print_value(itr->first, &itr->second);
	}
}
