#include <cstdio>
#include <iostream>
#include <fstream>
#include "webserv.hpp"
#include "Color.hpp"

// return 1 if test PASS, else 0
int	test_is_invalid_config_file_path(int test_no, const char *path, bool expected) {
	bool ret = is_valid_config_file_path(path);
	std::ifstream ifs;

	ifs.open(path, std::ifstream::in);

	printf("[TEST %02d] path:%s\n", test_no, path);
	printf("             ret_value :%s (ifs.open:%s)\n", ret ? GREEN "true" RESET : RED "false" RESET, ifs.is_open() ? GREEN "o" RESET : RED "x" RESET);
	printf("             expected  :%s\n", expected ? GREEN "true" RESET : RED "false" RESET);
	printf("             RESULT    :%s\n\n", ret == expected ? GREEN "OK" RESET : RED "KO" RESET);

	if (ifs.is_open()) {
		ifs.close();
	}
	return ret == expected ? 1 : 0;
}

int	main() {
	int ok_cnt = 0;
	int test_no = 0;

	std::cout << "-------------------- simple test --------------------" << std::endl;
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/file.conf", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/file.CONF", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/file.Conf", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/file.conF", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/file", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/nothing.conf", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/nothing", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/.conf", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/conf", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/a.conf", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/ a.conf", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/a.conf ", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/ a.conf ", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/a.b.conf", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/a.conf.b", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/conf.a", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/a.conf.", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, ".", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "..", false);
	std::cout << std::endl;

	std::cout << "-------------------- dir[rwx] --------------------" << std::endl;
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_rrr.conf", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_rr-.conf", true);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_r-r.conf", true);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_-rr.conf", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_r--.conf", true);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_-r-.conf", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_--r.conf", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_---.conf", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/this_is_dir.conf", false);

	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_rrr", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_rr-", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_r-r", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_-rr", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_r--", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_-r-", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_--r", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/dir/file_---", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/this_is_dir", false);
	std::cout << std::endl;

// git add permission denied
//	std::cout << "-------------------- dir[-wx] --------------------" << std::endl;
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_rrr.conf", true);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_rr-.conf", true);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_r-r.conf", true);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_-rr.conf", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_r--.conf", true);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_-r-.conf", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_--r.conf", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_---.conf", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/this_is_dir.conf", false);
//
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_rrr", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_rr-", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_r-r", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_-rr", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_r--", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_-r-", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_--r", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_r_dir/file_---", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/this_is_dir", false);
//	std::cout << std::endl;

	std::cout << "-------------------- dir[rw-] --------------------" << std::endl;
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_rrr.conf", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_rr-.conf", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_r-r.conf", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_-rr.conf", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_r--.conf", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_-r-.conf", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_--r.conf", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_---.conf", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/this_is_dir.conf", false);

	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_rrr", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_rr-", false);
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_r-r", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_-rr", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_r--", false);
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_-r-", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_--r", false);  //  git add permission denied
//	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/no_x_dir/file_---", false);  //  git add permission denied
	ok_cnt += test_is_invalid_config_file_path(++test_no, "files/this_is_dir", false);
	std::cout << std::endl;

	printf("############################################\n");
	printf(" TOTAL RESULT   OK %d/ total %d     %s\n", ok_cnt, test_no, test_no == ok_cnt ? GREEN "OK :)" RESET : RED "KO :X" RESET);
	printf("############################################\n\n");
	return 0;
}
