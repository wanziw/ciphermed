/*
 * Copyright 2013-2015 Raphael Bost
 *
 * This file is part of ciphermed.

 *  ciphermed is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 * 
 *  ciphermed is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 * 
 *  You should have received a copy of the GNU General Public License
 *  along with ciphermed.  If not, see <http://www.gnu.org/licenses/>. 2
 *
 */

#include <mpc/lsic.hh>
#include <mpc/private_comparison.hh>
#include <mpc/enc_comparison.hh>
#include <mpc/rev_enc_comparison.hh>
#include <mpc/linear_enc_argmax.hh>

#include <classifiers/linear_classifier.hh>

#include <protobuf/protobuf_conversion.hh>
#include <net/message_io.hh>
#include <util/util.hh>


Linear_Classifier_Server::Linear_Classifier_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &model, size_t bit_size)
: Server(state, Linear_Classifier_Server::key_deps_descriptor(), keysize, lambda), enc_model_(model.size()), bit_size_(bit_size)
{
    for (size_t i = 0; i < enc_model_.size(); i++) {
        enc_model_[i] = paillier_->encrypt(model[i]);
    }
}

Server_session* Linear_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Linear_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

void Linear_Classifier_Server_session::run_session()
{
    try {
        exchange_keys();
        
        ScopedTimer *t;
        RESET_BYTE_COUNT
        RESET_BENCHMARK_TIMER

        t = new ScopedTimer("Server: Compute dot product");
        help_compute_dot_product(linear_server_->enc_model(),true);
        delete t;
        
        t = new ScopedTimer("Server: Compare enc data");
        help_enc_comparison(linear_server_->bit_size(), GC_PROTOCOL);
        delete t;

#ifdef BENCHMARK
        cout << "Benchmark: " << GET_BENCHMARK_TIME << " ms" << endl;
        cout << IOBenchmark::byte_count() << " exchanged bytes" << endl;
        cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif

    } catch (std::exception& e) {
        std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}


Linear_Classifier_Client::Linear_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &vals, size_t bit_size)
: Client(io_service,state,Linear_Classifier_Server::key_deps_descriptor(),keysize,lambda), bit_size_(bit_size),values_(vals)
{
    
}

bool Linear_Classifier_Client::run()
{
    // get public keys
    RESET_BYTE_COUNT
    exchange_keys();
#ifdef BENCHMARK
    const double to_kB = 1 << 10;
    cout << "Key exchange: " <<  (IOBenchmark::byte_count()/to_kB) << " kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    
    ScopedTimer *t;
    RESET_BYTE_COUNT
    RESET_BENCHMARK_TIMER
    // prepare data
    vector <mpz_class> x = values_;
    x.push_back(-1);
    
    t = new ScopedTimer("Client: Compute dot product");
    // compute the dot product
    mpz_class v = compute_dot_product(x);
    mpz_class w = 1; // encryption of 0
    delete t;

    t = new ScopedTimer("Client: Compare enc data");
    // build the comparator over encrypted data
    bool result = enc_comparison(v,w,bit_size_,GC_PROTOCOL);
    delete t;
#ifdef BENCHMARK
    cout << "Benchmark: " << GET_BENCHMARK_TIME << " ms" << endl;
    cout << (IOBenchmark::byte_count()/to_kB) << " exchanged kB" << endl;
    cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    return result;
}


Bench_Linear_Classifier_Server::Bench_Linear_Classifier_Server(gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &model, size_t bit_size, unsigned int nRounds)
: Server(state, Linear_Classifier_Server::key_deps_descriptor(), keysize, lambda), enc_model_(model.size()), bit_size_(bit_size), nRounds_(nRounds)
{
#pragma omp parallel for
    for (size_t i = 0; i < enc_model_.size(); i++) {
	enc_model_[i] = model[i];
	//enc_model_[i] = paillier_->encrypt(model[i]);
    }
}

Server_session* Bench_Linear_Classifier_Server::create_new_server_session(tcp::socket &socket)
{
    return new Bench_Linear_Classifier_Server_session(this, rand_state_, n_clients_++, socket);
}

void Bench_Linear_Classifier_Server_session::run_session()
{
    try {
        exchange_keys();
        
        double server_time = 0.;
        unsigned int nRounds = linear_server_->nRounds();
        for (unsigned int i = 0; i < nRounds; i++) {
            RESET_BENCHMARK_TIMER
            
            help_compute_dot_product(linear_server_->enc_model(),true);
            
            help_enc_comparison(linear_server_->bit_size(), GC_PROTOCOL);

cout<<"\033[32m  ____                 _ ____             _ "<<endl;
cout<<"\033[32m / ___| ___   ___   __| | __ ) _   _  ___| |"<<endl;
cout<<"\033[32m| |  _ / _ \\ / _ \\ / _` |  _ \\| | | |/ _ \\ |"<<endl;
cout<<"\033[32m| |_| | (_) | (_) | (_| | |_) | |_| |  __/_|"<<endl;
cout<<"\033[32m \\____|\\___/ \\___/ \\__,_|____/ \\__, |\\___(_)"<<endl;
cout<<"\033[32m	                        |___/       "<<endl;
	
            
            server_time += GET_BENCHMARK_TIME;
//            cout << "Round #" << i << " done" << endl;
        }
#ifdef BENCHMARK
        cout << "Average time for " << nRounds << " rounds: " << endl;
        cout << "Server time: " << server_time/nRounds << endl;
#endif

    } catch (std::exception& e) {
        //std::cout << "Exception: " << e.what() << std::endl;
    }
    
    delete this;
}


Bench_Linear_Classifier_Client::Bench_Linear_Classifier_Client(boost::asio::io_service& io_service, gmp_randstate_t state, unsigned int keysize, unsigned int lambda, const vector<mpz_class> &vals, size_t bit_size, unsigned int nRounds)
: Client(io_service,state,Linear_Classifier_Server::key_deps_descriptor(),keysize,lambda), bit_size_(bit_size),values_(vals), nRounds_(nRounds)
{
    
}

void Bench_Linear_Classifier_Client::run(int num, int num2)
{
    // get public keys
    RESET_BYTE_COUNT
    exchange_keys();
#ifdef BENCHMARK
    const double to_kB = 1 << 10;
    //cout << "Key exchange: " <<  (IOBenchmark::byte_count()/to_kB) << " kB" << endl;
    //cout << IOBenchmark::interaction_count() << " interactions" << endl;
#endif
    double compare_time = 0., dot_prod_time = 0., client_time = 0.;
    Timer t;

    RESET_BYTE_COUNT

    cout<<"\033[32m  ____                            _   _                   "<<endl;
    cout<<"\033[32m / ___|___  _ __  _ __   ___  ___| |_(_)_ __   __ _       "<<endl;
    cout<<"\033[32m| |   / _ \\| '_ \\| '_ \\ / _ \\/ __| __| | '_ \\ / _` |      "<<endl;
    cout<<"\033[32m| |__| (_) | | | | | | |  __/ (__| |_| | | | | (_| |_ _ _ "<<endl;
    cout<<"\033[32m \\____\\___/|_| |_|_| |_|\\___|\\___|\\__|_|_| |_|\\__, (_|_|_)"<<endl;
    cout<<"\033[32m			                      |___/       "<<endl;

	//ifstream fin1("../../classifiers/lbp_lfw1000.out");
	ifstream fin1("../../classifiers/testLFW.out");
	ifstream fin2("../../classifiers/A1000.out");
	ifstream fin3("../../classifiers/G1000.out");

	vector<vector<mpz_class> > myV;
	vector<vector<mpz_class> > myA;
	vector<vector<mpz_class> > myG;
	myV.resize(12792, vector<mpz_class>(160, 0));
	myA.resize(160,   vector<mpz_class>(160, 0));
	myG.resize(160,   vector<mpz_class>(160, 0));

	double dt;
	long ltmp;
	for(int i = 0; i < 160; i++) 
	    for(int j = 0; j < 160; j++) {
		if(i < 160) {
		    fin2>>dt;
		    ltmp = dt * 1e5;
		    myA[i][j] = ltmp;
		    fin3>>dt;
		    ltmp = dt * 1e5;
		    myG[i][j] = ltmp;
		}
		if( i < 20) {
		fin1>>dt;
		ltmp = dt * 1e5;
		myV[i][j] = ltmp;
		}
	    }

	Paillier &p = *server_paillier_;
	vector<mpz_class> myX(160);
	vector<mpz_class> myY(160);
	vector<mpz_class> myGG(160);
	vector<mpz_class> myXX(25600);
	vector<mpz_class> myYY(25600);
	vector<mpz_class> myAY(25600);
	mpz_class totA = 0;
	mpz_class totA2 = 0;
	mpz_class totG = 1;
	mpz_class tot = 0;
	mpz_class tmp = 0;

	for(int i = 0; i < 160; i++) {
	    myX[i] = myV[num][i];
	    myY[i] = myV[num2][i];
	}
	vector<mpz_class> myGY = compute_dot_product2();

	for(int i = 0; i < 160; i++)
	    for(int j = 0; j < 160; j++)
		myGG[i] += myX[j] * myG[j][i];

#pragma omp parallel for
	for(int i = 0; i < 160; i++)
	    for(int j = 0; j < 160; j++) {
		myXX[i * 160 + j] = myX[i] * myX[j];
		myYY[i * 160 + j] = myY[i] * myY[j];
	    }

#pragma omp parallel for
	for(int i = 0; i < 13; i++)
	    for(int j = 0; j < 160; j++)
		if(i * 160 + j < 2000)
		    myYY[i * 160 + j] = p.encrypt(myY[i] * myY[j]);

	for(int i = 0; i < 160; i++)
	    for(int j = 0; j < 160; j++) {
		totA += myXX[i * 160 + j] * myA[i][j];
		if(i * 160 + j >= 2000)
		    totA2 += myYY[i * 160 + j] * myA[i][j];
		//totA2 = p.add(totA2, p.constMult(myA[i][j], p.encrypt(myYY[i*160+j])));
		//totA2 += myYY[i * 160 + j] * myA[i][j];
		if(i == 0)
		    totG = p.add(totG, p.constMult(myGG[j], p.encrypt(myY[j])));
		    //totG += myGG[j] * myY[j];
	    }

#pragma omp parallel for
	for(int i = 0; i < 160; i++)
	    for(int j = 0; j < 160; j++)
		if( i * 160 + j < 2000)
		    myAY[i * 160 + j] = p.constMult(myA[i][j], myYY[i * 160 + j]);

	totA2 = p.encrypt(totA2);
	for(int i = 0; i < 2000; i++)
	    totA2 = p.add(totA2, myAY[i]);


	//tot = totA + totA2 - 2 * totG;
	//tot = totA + totA2;
	tot = totA;
	tot = p.add(p.encrypt(tot), totA2);
	//tot = p.encrypt(tot);
	tot = p.add(tot, p.constMult(-2, totG));
	tmp = 169 * 1e14;
	tot = p.add(tot, p.encrypt(tmp));


	
        RESET_BENCHMARK_TIMER

        // compute the dot product
        mpz_class w = 1; // encryption of 0
        
        //dot_prod_time += t.lap_ms();
	t.lap();
        // build the comparator over encrypted data
        bool result = enc_comparison(tot,w,bit_size_,GC_PROTOCOL);	
	if(result == 0) {
	    cout<<"\033[32m __        __   _                            _   _                      _ "<<endl;
	    cout<<"\033[32m \\ \\      / /__| | ___ ___  _ __ ___   ___  | | | | ___  _ __ ___   ___| |"<<endl;
	    cout<<"\033[32m  \\ \\ /\\ / / _ \\ |/ __/ _ \\| '_ ` _ \\ / _ \\ | |_| |/ _ \\| '_ ` _ \\ / _ \\ |"<<endl;
	    cout<<"\033[32m   \\ V  V /  __/ | (_| (_) | | | | | |  __/ |  _  | (_) | | | | | |  __/_|"<<endl;
	    cout<<"\033[32m    \\_/\\_/ \\___|_|\\___\\___/|_| |_| |_|\\___| |_| |_|\\___/|_| |_| |_|\\___(_)"<<endl;
	}
	else{
	    cout<<"\033[31m  _____                _               _       _ "<<endl;
	    cout<<"\033[31m |_   _| __ _   _     / \\   __ _  __ _(_)_ __ | |"<<endl;
	    cout<<"\033[31m   | || '__| | | |   / _ \\ / _` |/ _` | | '_ \\| |"<<endl;
	    cout<<"\033[31m   | || |  | |_| |  / ___ \\ (_| | (_| | | | | |_|"<<endl;
	    cout<<"\033[31m   |_||_|   \\__, | /_/   \\_\\__, |\\__,_|_|_| |_(_)"<<endl;
	    cout<<"\033[31m	     |___/          |___/                 "<<endl;
	}

        compare_time += t.lap_ms();

        client_time += GET_BENCHMARK_TIME;

}
