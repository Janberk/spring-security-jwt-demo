package com.dasburo.ssjwtdemo.student;

import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "James Bond"),
            new Student(2, "Maria Jones"),
            new Student(3, "Anna Smith")
    );

    @GetMapping
    public List<Student> readAll() {
        return STUDENTS;
    }

    @GetMapping(path = "{studentId}")
    public Student read(@PathVariable("studentId") Integer studentId) {
        return STUDENTS
                .stream()
                .filter(student -> {
                    return student.getStudentId().equals(studentId);
                })
                .findFirst().orElse(null);
    }

    @PostMapping
    public void create(@RequestBody Student student) {
        System.out.println(student);
    }

    @DeleteMapping(path = "{studentId}")
    public void delete(@PathVariable("studentId") Integer studentId) {
        System.out.println(studentId);
    }

    @PutMapping(path = "{studentId}")
    public void update(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.printf("%s %s%n", studentId, student);
    }

}
