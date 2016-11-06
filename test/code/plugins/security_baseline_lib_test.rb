require 'test/unit'
require_relative 'omstestlib'
require_relative ENV['BASE_DIR'] + '/source/code/plugins/security_baseline_lib'

class BaselineLibTest < Test::Unit::TestCase
    def setup
        OMS::SecurityBaseline.log = OMS::MockLog.new
    end    
    
    def test_baseline_with_corect_input

        baseline_results_str = '{ "baseline_id": "OMS.Linux.1", "base_orig_id": "1", "setting_count": 2, "scan_time": "2016-09-21T10:19:00.66205592Z", "results": [ { "msid": "2.1", "result": "PASS", "error_text": "", "cceid": "CCE-3522-0", "severity": "Important", "description": "The nodev option should be enabled for all removable media." }, { "msid": "6.1", "result": "FAIL", "error_text": "Found no files matching ^install cramfs in /etc/modprobe.d/", "cceid": "CCE-14089-7", "severity": "Warning", "description": "Disable the installation and use of file systems that are not required (cramfs)" } ] }'    
        baseline_results_json = JSON.parse(baseline_results_str)

        baseline_results_json["assessment_id"] = "3af00be8-44b9-4925-a64a-d5fd3241ddd3"
        
        security_baseline_blob, security_baseline_summary_blob = OMS::SecurityBaseline.transform_and_wrap(baseline_results_json, "test_host", "")        
        
        assert_equal(security_baseline_blob["DataType"], "SECURITY_BASELINE_BLOB", "Incorrect 'DataType' value") 
        assert_equal(security_baseline_blob["IPName"], "Security", "Incorrect 'IPName' value")
        
        baseline_item_0 = security_baseline_blob["DataItems"][0]
        assert_equal(baseline_item_0["TimeAnalyzed"], "2016-09-21T10:19:00.66205592Z", "Incorrect 'TimeAnalyzed' value")
        assert_equal(baseline_item_0["Computer"], "test_host", "Incorrect 'Computer' value")
        assert_equal(baseline_item_0["CceId"], "CCE-3522-0", "Incorrect 'CceId' value")
        assert_equal(baseline_item_0["Severity"], "Important", "Incorrect 'Severity' value")
        assert_equal(baseline_item_0["Name"], "The nodev option should be enabled for all removable media.", "Incorrect 'Name' value")
        assert_equal(baseline_item_0["AnalyzeResult"], "Passed", "Incorrect 'AnalyzeResult' value")
        assert_not_equal(baseline_item_0["AssessmentId"], "3af00be8-44b9-4925-a64a-d5fd3241ddd3", "Incorrect 'AssessmentId' value")
        assert_equal(baseline_item_0["OSName"], "Linux", "Incorrect 'OSName' value")
        assert_equal(baseline_item_0["RuleType"], "Command", "Incorrect 'RuleType' value")
        
        baseline_item_1 = security_baseline_blob["DataItems"][1]
        assert_equal(baseline_item_1["TimeAnalyzed"], "2016-09-21T10:19:00.66205592Z", "Incorrect 'TimeAnalyzed' value")
        assert_equal(baseline_item_1["Computer"], "test_host", "Incorrect 'Computer' value")
        assert_equal(baseline_item_1["CceId"], "CCE-14089-7", "Incorrect 'CceId' value")
        assert_equal(baseline_item_1["Severity"], "Warning", "Incorrect 'Severity' value")
        assert_equal(baseline_item_1["Name"], "Disable the installation and use of file systems that are not required (cramfs)", "Incorrect 'Name' value")
        assert_equal(baseline_item_1["AnalyzeResult"], "Failed", "Incorrect 'AnalyzeResult' value")
        assert_not_equal(baseline_item_1["AssessmentId"], "3af00be8-44b9-4925-a64a-d5fd3241ddd3", "Incorrect 'AssessmentId' value")
        assert_equal(baseline_item_1["OSName"], "Linux", "Incorrect 'OSName' value")        
        assert_equal(baseline_item_1["RuleType"], "Command", "Incorrect 'RuleType' value")

        assert_equal(security_baseline_summary_blob["DataType"], "SECURITY_BASELINE_SUMMARY_BLOB", "Incorrect 'DataType' value") 
        assert_equal(security_baseline_summary_blob["IPName"], "Security", "Incorrect 'IPName' value")
        
        baseline_summary_item = security_baseline_summary_blob["DataItems"][0]
        assert_equal(baseline_summary_item["Computer"], "test_host", "Incorrect 'Computer' value")
        assert_equal(baseline_summary_item["TotalAssessedRules"], 2, "Incorrect 'TotalAssessedRules' value")
        assert_equal(baseline_summary_item["CriticalFailedRules"], 0, "Incorrect 'CriticalFailedRules' value")
        assert_equal(baseline_summary_item["WarningFailedRules"], 1, "Incorrect 'WarningFailedRules' value")
        assert_equal(baseline_summary_item["InformationalFailedRules"], 0, "Incorrect 'InformationalFailedRules' value")
        assert_equal(baseline_summary_item["PercentageOfPassedRules"], 50, "Incorrect 'PercentageOfPassedRules' value")
        assert_not_equal(baseline_summary_item["AssessmentId"], "3af00be8-44b9-4925-a64a-d5fd3241ddd3", "Incorrect 'AssessmentId' value")
        assert_equal(baseline_summary_item["OSName"], "Linux", "Incorrect 'OSName' value")
        
        assert_equal(baseline_item_0["AssessmentId"], baseline_summary_item["AssessmentId"], "Different 'AssessmentId' between baseline and baseline summary")
    end

    def test_baseline_with_empty_input
        baseline_results_json = nil
      
        security_baseline_blob, security_baseline_summary_blob = OMS::SecurityBaseline.transform_and_wrap(baseline_results_json, "test_host", "")        
        
        assert_equal(security_baseline_blob, nil, "Incorrect error case support") 
        assert_equal(security_baseline_summary_blob, nil, "Incorrect error case support") 
    end

    def test_baseline_with_bad_input
        baseline_results_str = '{ "baseline_id": "OMS.Linux.1" }'    
        baseline_results_json = JSON.parse(baseline_results_str)
      
        security_baseline_blob, security_baseline_summary_blob = OMS::SecurityBaseline.transform_and_wrap(baseline_results_json, "test_host", "")        
        
		assert_equal(security_baseline_blob, nil, "Incorrect error case support") 
        assert_equal(security_baseline_summary_blob, nil, "Incorrect error case support") 
    end
end
